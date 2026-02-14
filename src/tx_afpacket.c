#define _GNU_SOURCE
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

    /* Link layer setup. */
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

int tx_send_batch(const tx_ctx_t *tx, const uint8_t *const *frames, const size_t *lens, int count) {
    if (!tx || tx->sock_fd < 0 || !frames || !lens || count <= 0) {
        return 0;
    }

    if (count > TX_BATCH_MAX) {
        count = TX_BATCH_MAX;
    }

    /* Single sockaddr_ll reused for all packets in batch. */
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = tx->ifindex;
    addr.sll_halen = ETH_ALEN;

    struct iovec iovecs[TX_BATCH_MAX]; /* Scatter/gather buffers */
    struct mmsghdr msgs[TX_BATCH_MAX]; /* Batch of messages for sendmmsg */
    memset(msgs, 0, sizeof(struct mmsghdr) * (size_t)count);

    for (int i = 0; i < count; i++) {
        /* Cast away const from frames[i] so we can assign to iov_base.
         * iovec uses void* (not const void*). */
        iovecs[i].iov_base = (void *)frames[i];
        iovecs[i].iov_len = lens[i]; /* Buffer length */

        msgs[i].msg_hdr.msg_name = &addr; /* Destination (same for all) */
        msgs[i].msg_hdr.msg_namelen = sizeof(addr);
        msgs[i].msg_hdr.msg_iov = &iovecs[i]; /* Buffer array */
        msgs[i].msg_hdr.msg_iovlen = 1;       /* Single buffer per message */
    }

    int sent = sendmmsg(tx->sock_fd, msgs, (unsigned int)count, 0);

    if (sent < 0) {
        log_msg(LOG_WARN, "sendmmsg failed: %s", strerror(errno));
        return 0;
    }

    return sent;
}

void tx_close(tx_ctx_t *tx) {
    if (!tx) return;
    if (tx->sock_fd >= 0) close(tx->sock_fd);
    tx->sock_fd = -1;
    tx->ifindex = 0;
}