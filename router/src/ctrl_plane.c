#include <arpa/inet.h>
#include <pthread.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "ctrl_plane.h"

static struct rte_mempool *g_pool;

#define RTE_LOGTYPE_CTRL RTE_LOGTYPE_USER1

static rx_lcore_ctx_t *g_ctx;
static int server_fd = -1;
static uint32_t g_endpoint_ip[MAX_PORTS];

static void handle_add_vhost(char *args) {
    char endpoint_id[32], ip_str[32], mac_str[32], gw_str[32];

    if (sscanf(args, "%31s %31s %31s %31s", endpoint_id, ip_str, mac_str, gw_str) != 4) {
        RTE_LOG(ERR, CTRL, "IPC: Invalid ADD_VHOST args\n");
        return;
    }

    /* Virtual Device Arguments */
    char vdev_args[128];
    char vdev_name[64];

    snprintf(vdev_name, sizeof(vdev_name), "net_vhost_%s", endpoint_id);

    snprintf(vdev_args, sizeof(vdev_args), "iface=/var/run/upe/%s.sock,client=0,queues=1",
             endpoint_id);

    RTE_LOG(INFO, CTRL, "Hotplugging %s with args: %s\n", vdev_name, vdev_args);

    if (rte_eal_hotplug_add("vdev", vdev_name, vdev_args) < 0) {
        RTE_LOG(ERR, CTRL, "Failed to hotplug vhost-user port %s\n", vdev_name);
        return;
    }

    uint16_t port_id;
    if (rte_eth_dev_get_port_by_name(vdev_name, &port_id) != 0) {
        RTE_LOG(ERR, CTRL, "Could not find hotplugged port %s\n", vdev_name);
        return;
    }

    /* Init the port with RX/TX rings, start the device */
    if (port_init(port_id, g_pool, 0) != 0) {
        RTE_LOG(ERR, CTRL, "Failed to initialize port %d\n", port_id);
        return;
    }

    struct rte_ether_addr endpoint_mac, router_mac;
    rte_ether_unformat_addr(mac_str, &endpoint_mac);
    rte_eth_macaddr_get(port_id, &router_mac);

    uint32_t endpoint_ip = inet_addr(ip_str);
    uint32_t gw_ip = inet_addr(gw_str);

    rte_ether_addr_copy(&router_mac, (struct rte_ether_addr *)g_ctx->ifaces[port_id].mac);
    g_ctx->ifaces[port_id].ip = gw_ip;
    g_ctx->ifaces[port_id].is_nat_outside = false;
    g_ctx->ifaces[port_id].configured = true;

    g_endpoint_ip[port_id] = endpoint_ip;

    /* Seed ARP as we already know the endpoint's MAC, don't trigger pointless ARP exchange from the
     * 1st packet */
    arp4_insert(&g_ctx->arp4, endpoint_ip, endpoint_mac.addr_bytes);

    /* /32 host route to the endpoint. */
    lpm_insert(&g_ctx->lpm, endpoint_ip, 32, endpoint_ip, port_id);

    /* Signal the packet loops in the fast path by flipping the bit */
    __atomic_or_fetch(&g_ctx->active_ports_mask, (1ULL << port_id), __ATOMIC_RELEASE);
}

static void handle_del_vhost(char *args) {
    char endpoint_id[32];

    if (sscanf(args, "%31s", endpoint_id) != 1) {
        RTE_LOG(ERR, CTRL, "IPC: Invalid DEL_VHOST args\n");
        return;
    }

    char vdev_name[64];
    snprintf(vdev_name, sizeof(vdev_name), "net_vhost_%s", endpoint_id);

    uint16_t port_id;
    if (rte_eth_dev_get_port_by_name(vdev_name, &port_id) != 0) {
        RTE_LOG(ERR, CTRL, "Could not find hotplugged port %s to delete\n", vdev_name);
        return;
    }

    /* Stop fast path from polling this port */
    __atomic_and_fetch(&g_ctx->active_ports_mask, ~(1ULL << port_id), __ATOMIC_RELEASE);

    /* Wait a bit for fast path */
    usleep(1000);

    uint32_t ip = g_ctx->ifaces[port_id].ip;
    lpm_delete(&g_ctx->lpm, ip, 32);

    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);

    if (rte_eal_hotplug_remove("vdev", vdev_name) != 0) {
        RTE_LOG(ERR, CTRL, "Failed to remove vdev %s\n", vdev_name);
    }

    g_ctx->ifaces[port_id].configured = false;
    g_ctx->ifaces[port_id].ip = 0;

    RTE_LOG(INFO, CTRL, "Successfully deleted vhost-user %s on Port %d\n", endpoint_id, port_id);
}

/* handle_client: Read the command over the UNIX socket. */
static void handle_client(int client_fd) {
    char buf[512];

    ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    buf[n] = '\0';

    /* First word: command, rest: args */
    char cmd[32], args[256];
    int parsed = sscanf(buf, "%31s %255[^\n]", cmd, args);

    if (parsed >= 2) {
        if (strcmp(cmd, "ADD_VHOST") == 0) {
            handle_add_vhost(args);
        } else if (strcmp(cmd, "DEL_VHOST") == 0) {
            handle_del_vhost(args);
        } else {
            RTE_LOG(WARNING, CTRL, "Unknown IPC command: %s\n", cmd);
        }
    } else {
        RTE_LOG(WARNING, CTRL, "Malformed IPC command received.\n");
    }

    close(client_fd);
}

/* ctrl_plane_thread: Listen for connections. */
static void *ctrl_plane_thread(void *arg) {
    (void)arg;

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) return NULL;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, UPE_IPC_SOCKET, sizeof(addr.sun_path) - 1);

    /* Remove any leftover socket file. */
    unlink(UPE_IPC_SOCKET);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(server_fd);
        return NULL;
    }

    chmod(UPE_IPC_SOCKET, 0600);

    /* Queue up to 10 incoming client connections at once. */
    listen(server_fd, 10);

    RTE_LOG(INFO, CTRL, "Control Plane listening on %s\n", UPE_IPC_SOCKET);

    while (g_ctx && !g_ctx->stop) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd >= 0) {
            handle_client(client_fd);
        }
    }

    close(server_fd);
    unlink(UPE_IPC_SOCKET);
    return NULL;
}

int ctrl_plane_start(rx_lcore_ctx_t *ctx, struct rte_mempool *pool) {
    g_ctx = ctx;
    g_pool = pool;

    system("mkdir -p /var/run/upe");

    pthread_t thread;
    if (pthread_create(&thread, NULL, ctrl_plane_thread, NULL) != 0) {
        return -1;
    }

    pthread_detach(thread);
    return 0;
}