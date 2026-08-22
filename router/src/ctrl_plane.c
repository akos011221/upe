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

static int attach_tap_port(const char *port_name, const char *devargs) {
    uint16_t port_id;

    int ret = rte_eal_hotplug_add("vdev", port_name, devargs);
    if (ret < 0) {
        RTE_LOG(ERR, CTRL, "Failed to hotplug %s: %s\n", port_name, strerror(-ret));
        return ret;
    }

    ret = rte_eth_dev_get_port_by_name(port_name, &port_id);
    if (ret < 0) return ret;

    ret = port_init(port_id, g_pool, 0);
    if (ret < 0) {
        RTE_LOG(ERR, CTRL, "Failed to init hotplugged port %d\n", port_id);
        return ret;
    }

    return port_id;
}

/* handle_client: Read the command from the CNI script over the UNIX socket. */
static void handle_client(int client_fd) {
    char buf[512];

    ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    buf[n] = '\0';

    /* Expectation is that the command formatted as:
     * "ADD_VHOST examplepod 10.128.0.50 00:11:22:33:44:55" */
    char cmd[32], pod_id[64], ip_str[32], mac_str[32];
    int parsed = sscanf(buf, "%31s %63s %31s %31s", cmd, pod_id, ip_str, mac_str);

    if (parsed >= 2) {
        if (strcmp(cmd, "ADD_TAP") == 0 && parsed == 4) {
            char port_name[64];
            snprintf(port_name, sizeof(port_name), "net_tap_%s", pod_id);

            char devargs[128];
            snprintf(devargs, sizeof(devargs), "iface=tap_%s", pod_id);

            RTE_LOG(INFO, CTRL, "IPC received: attaching %s with %s\n", port_name, devargs);

            int port_id = attach_tap_port(port_name, devargs);
            if (port_id >= 0 && port_id < MAX_PORTS) {
                /* Parse the IPv4 address. */
                struct in_addr addr;
                if (inet_pton(AF_INET, ip_str, &addr) == 1) {
                    g_ctx->ifaces[port_id].ip = addr.s_addr;
                    g_ctx->ifaces[port_id].netmask = 0xFFFFFFFF;

                    /* Insert it into the DPDK LPM Table. */
                    if (lpm_insert(&g_ctx->lpm, addr.s_addr, 32, addr.s_addr, port_id) == true) {
                        RTE_LOG(INFO, CTRL, "LPM injected: Route %s/32 -> Port %d\n", ip_str,
                                port_id);
                    }
                }

                /* Parse the MAC Address. */
                uint8_t mac[6];
                if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2],
                           &mac[3], &mac[4], &mac[5]) == 6) {
                    memcpy(g_ctx->ifaces[port_id].mac, mac, 6);
                }

                g_ctx->ifaces[port_id].configured = true;

                /* To avoid lock contention in the rx_lcore polling loop, notify it about the new
                 * port using atomic bitmask. */
                __atomic_or_fetch(&g_ctx->active_ports_mask, (1ULL << port_id), __ATOMIC_RELEASE);

                /* Response to the CNI. */
                const char *resp = "OK\n";
                write(client_fd, resp, strlen(resp));
            } else {
                const char *resp = "ERR\n";
                write(client_fd, resp, strlen(resp));
            }

        } else if (strcmp(cmd, "DEL_TAP") == 0 && parsed == 2) {
            char port_name[64];
            snprintf(port_name, sizeof(port_name), "net_tap_%s", pod_id);

            uint16_t port_id;
            if (rte_eth_dev_get_port_by_name(port_name, &port_id) == 0) {
                // Stop lx_lcore from polling this port right now.
                __atomic_and_fetch(&g_ctx->active_ports_mask, ~(1ULL << port_id), __ATOMIC_RELEASE);

                usleep(1000);

                uint32_t ip = g_ctx->ifaces[port_id].ip;
                lpm_delete(&g_ctx->lpm, ip, 32);

                rte_eth_dev_stop(port_id);
                rte_eth_dev_close(port_id);

                rte_eal_hotplug_remove("vdev", port_name);

                g_ctx->ifaces[port_id].configured = false;

                RTE_LOG(INFO, CTRL, "IPC received: destroyed %s\n", port_name);

                const char *resp = "OK\n";
                write(client_fd, resp, strlen(resp));
            } else {
                const char *resp = "ERR\n";
                write(client_fd, resp, strlen(resp));
            }
        }
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

    /* Queue up to 10 incoming CNI connections at once. */
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