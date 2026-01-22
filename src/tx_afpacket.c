#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "log.h"
#include "tx.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

int tx_init(tx_ctx_t *tx, const char *out_iface) {
    if (!tx || !out_iface) return -1;

    memset(tx, 0, sizeof(*tx));

    int ifindex = (int)if_nametoindex(out_iface);
    if (ifindex == 0) {
        log_msg(LOG_ERROR, "if_nametoindex(%s) failed: %s", out_iface, strerror(errno));
        return -1;
    }

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        log_msg(LOG_ERROR, "socket(AF_PACKET) failed: %s", strerror(errno));
        return -1;
    }

    /* Get MAC address of the interface */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, out_iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        log_msg(LOG_ERROR, "ioctl(SIOCGIFHWADDR) failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    tx->sock_fd = fd;
    tx->ifindex = ifindex;
    memcpy(tx->eth_addr, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

int tx_send(const tx_ctx_t *tx, const uint8_t *frame, size_t len) {
    if (!tx || tx->sock_fd < 0 || !frame || len == 0) return -1;

    // Link layer address setup.
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = tx->ifindex;
    addr.sll_halen = ETH_ALEN; // MAC address

    ssize_t rc = sendto(tx->sock_fd, frame, len, 0, (struct sockaddr *)&addr, sizeof(addr));

    if (rc < 0) {
        return -1;
    }
    return 0;
}

void tx_close(tx_ctx_t *tx) {
    if (!tx) return;
    if (tx->sock_fd >= 0) close(tx->sock_fd);
    tx->sock_fd = -1;
    tx->ifindex = 0;
}