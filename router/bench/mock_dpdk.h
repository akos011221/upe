#ifndef MOCK_DPDK_H
#define MOCK_DPDK_H

/* Redirect rdtsc to an ignored name */
#define rdtsc hardware_rdtsc_ignored

/* Force latency.h (which defined rdtsc()) to load. It will define hardware_rdtsc_ignored instead. */
#include "latency.h"

/* Undefine the redirection so we can use the clean rdtsc name */
#undef rdtsc

/* Header guard intercept so rx_lcore.c won't try to find DPDK system headers */
#define _RTE_EAL_H_
#define _RTE_ETHDEV_H_
#define _RTE_ETHER_H_
#define _RTE_MBUF_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define MAC_ADDR_LEN 6
#define RTE_PKTMBUF_HEADROOM 128
#define NUM_PORTS 2
#define BURST_SIZE 32
#define MOCK_MBUF_SIZE 2048

/* Ethernet header definition (rte_ether.h) */
struct rte_ether_addr {
    uint8_t addr_bytes[6];
};

struct rte_ether_hdr {
    struct rte_ether_addr dst_addr;
    struct rte_ether_addr src_addr;
    uint16_t ether_type;
} __attribute__((__packed__));

/* Fake DPDK mbuf structure */
struct rte_mbuf {
    uint32_t pkt_len;
    uint16_t data_len;
    uint16_t port;
    void *buf_addr;
    void *pool;
    char data_buf[MOCK_MBUF_SIZE];
};

/* Mock macro to get data pointer and cast it to the requested type */
#define rte_pktmbuf_mtod(m, t) ((t)((char *)(m)->buf_addr))

/* Global counters */
extern uint32_t mock_mbuf_allocated;
extern uint32_t mock_mbuf_freed;

/* Mock DPDK memory management */
static inline struct rte_mbuf *rte_pktmbuf_alloc(void *pool) {
    (void)pool;
    struct rte_mbuf *m = (struct rte_mbuf *)malloc(sizeof(struct rte_mbuf));
    if (m) {
        memset(m, 0, sizeof(struct rte_mbuf));
        m->buf_addr = m->data_buf + RTE_PKTMBUF_HEADROOM;
        m->pool = pool;
        mock_mbuf_allocated++;
    }
    return m;
}

static inline void rte_pktmbuf_free(struct rte_mbuf *m) {
    if (m) {
        mock_mbuf_freed++;
        free(m);
    }
}

static inline struct rte_mbuf *rte_pktmbuf_copy(const struct rte_mbuf *m, void *pool, uint32_t offset, uint32_t length) {
    (void)offset;
    (void)length;
    if (!m) return NULL;
    struct rte_mbuf *clone = rte_pktmbuf_alloc(pool);
    if (clone) {
        clone->pkt_len = m->pkt_len;
        clone->data_len = m->data_len;
        clone->port = m->port;
        memcpy(clone->data_buf, m->data_buf, sizeof(m->data_buf));
    }
    return clone;
}

/* Helper to build test packets */
static inline struct rte_mbuf *mock_build_packet(uint16_t port, const uint8_t *src_mac, const uint8_t *dst_mac, uint16_t ethertype) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(NULL);
    if (!m) return NULL;

    m->port = port;
    uint8_t *pkt = (uint8_t *)m->buf_addr;

    memcpy(pkt, dst_mac, 6);
    memcpy(pkt + 6, src_mac, 6);
    pkt[12] = (ethertype >> 8) & 0xFF;
    pkt[13] = ethertype & 0xFF;

    m->data_len = 14;
    m->pkt_len = 14;
    return m;
}

static inline uint64_t rdtsc(void) {
    static uint64_t mock_tsc = 1000000;
    return mock_tsc++;
}

/* Mock that the NIC hardware accepted the packets */
static inline uint16_t rte_eth_tx_burst(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts) {
    (void)port_id;
    (void)queue_id;
    (void)tx_pkts;
    return nb_pkts; /* Pretend all were successfully transmitted */
}

/* Mock lcore utility */
static inline unsigned int rte_lcore_id(void) {
    return 0;
}

/* Mock RX burst function */
static inline uint16_t rte_eth_rx_burst(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **rx_pkts, uint16_t nb_pkts) {
    (void)port_id;
    (void)queue_id;
    (void)rx_pkts;
    (void)nb_pkts;
    return 0;
}

#endif // MOCK_DPDK_H
