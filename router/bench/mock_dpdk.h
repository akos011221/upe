#ifndef MOCK_DPDK_H
#define MOCK_DPDK_H

/* Redirect rdtsc to an ignored name */
#define rdtsc hardware_rdtsc_ignored

/* Force latency.h (which defined rdtsc()) to load. It will define hardware_rdtsc_ignored instead.
 */
#include "latency.h"

/* Undefine the redirection so we can use the clean rdtsc name */
#undef rdtsc

/* Header guard intercept so rx_lcore.c won't try to find DPDK system headers */
#define _RTE_EAL_H_
#define _RTE_ETHDEV_H_
#define _RTE_ETHER_H_
#define _RTE_MBUF_H_
#define _RTE_IP_H_
#define _RTE_ARP_H_
#define _RTE_ICMP_H_
#define _RTE_BYTEORDER_H_
#define _RTE_BYTEORDER_X86_H_
#define _RTE_BYTEORDER_ARM_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAC_ADDR_LEN 6
#define RTE_PKTMBUF_HEADROOM 128
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
    uint16_t refcnt;
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
        m->refcnt = 1;
        mock_mbuf_allocated++;
    }
    return m;
}

static inline void rte_pktmbuf_free(struct rte_mbuf *m) {
    if (m) {
        m->refcnt--;
        if (m->refcnt == 0) {
            mock_mbuf_freed++;
            free(m);
        }
    }
}

/* Copies metadata only and shares the parent's payload (by copying just the pointer addr) */
static inline struct rte_mbuf *rte_pktmbuf_clone(struct rte_mbuf *md, void *mp) {
    (void)mp;
    if (!md) return NULL;

    /* Create a new metadata shell, point buf_addr to the parent's data buffer */
    struct rte_mbuf *clone = (struct rte_mbuf *)malloc(sizeof(struct rte_mbuf));
    if (clone) {
        clone->pkt_len = md->pkt_len;
        clone->data_len = md->data_len;
        clone->port = md->port;
        clone->pool = md->pool;
        clone->buf_addr = md->buf_addr;
        clone->refcnt = 1;

        md->refcnt++; /* Parent's ref count must be increased */
        mock_mbuf_allocated++;
    }
    return clone;
}

/* Deep copies the whole packet, allocating new memory for the payload as well */
static inline struct rte_mbuf *rte_pktmbuf_copy(const struct rte_mbuf *m, void *pool,
                                                uint32_t offset, uint32_t length) {
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
static inline struct rte_mbuf *mock_build_packet(uint16_t port, const uint8_t *src_mac,
                                                 const uint8_t *dst_mac, uint16_t ethertype) {
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
static inline uint16_t rte_eth_tx_burst(uint16_t port_id, uint16_t queue_id,
                                        struct rte_mbuf **tx_pkts, uint16_t nb_pkts) {
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
static inline uint16_t rte_eth_rx_burst(uint16_t port_id, uint16_t queue_id,
                                        struct rte_mbuf **rx_pkts, uint16_t nb_pkts) {
    (void)port_id;
    (void)queue_id;
    (void)rx_pkts;
    (void)nb_pkts;
    return 0;
}

/* L3 DPDK MOCKS */
#define rte_pktmbuf_mtod_offset(m, t, o) ((t)((char *)(m)->buf_addr + (o)))
#define rte_be_to_cpu_16(x) __builtin_bswap16(x)
#define rte_be_to_cpu_32(x) __builtin_bswap32(x)
#define rte_cpu_to_be_16(x) __builtin_bswap16(x)
#define rte_cpu_to_be_32(x) __builtin_bswap32(x)

#define RTE_ETHER_TYPE_IPV4 0x0800
#define RTE_IPV4(a, b, c, d)                                                                       \
    ((uint32_t)(((a) & 0xff) << 24) | (((b) & 0xff) << 16) | (((c) & 0xff) << 8) | ((d) & 0xff))
#define IPPROTO_ICMP 1
#define RTE_ETHER_TYPE_ARP 0x0806
#define RTE_ARP_HRD_ETHER 1
#define RTE_ARP_OP_REQUEST 1
#define RTE_ARP_OP_REPLY 2

static inline void rte_ether_addr_copy(const struct rte_ether_addr *ea_from,
                                       struct rte_ether_addr *ea_to) {
    *ea_to = *ea_from;
}

struct rte_ipv4_hdr {
    uint8_t version_ihl;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t packet_id;
    uint16_t fragment_offset;
    uint8_t time_to_live;
    uint8_t next_proto_id;
    uint16_t hdr_checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
} __attribute__((__packed__));

static inline uint16_t rte_ipv4_cksum(const struct rte_ipv4_hdr *ipv4_hdr) {
    (void)ipv4_hdr;
    return 0;
}

struct rte_arp_ipv4 {
    struct rte_ether_addr arp_sha;
    uint32_t arp_sip;
    struct rte_ether_addr arp_tha;
    uint32_t arp_tip;
} __attribute__((__packed__));

struct rte_arp_hdr {
    uint16_t arp_hardware;
    uint16_t arp_protocol;
    uint8_t arp_hlen;
    uint8_t arp_plen;
    uint16_t arp_opcode;
    struct rte_arp_ipv4 arp_data;
} __attribute__((__packed__));

#define RTE_IP_ICMP_ECHO_REPLY 0
#define RTE_IP_ICMP_ECHO_REQUEST 8

struct rte_icmp_hdr {
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_cksum;
    uint16_t icmp_ident;
    uint16_t icmp_seq_nb;
} __attribute__((__packed__));

static inline uint16_t rte_raw_cksum(const void *buf, size_t len) {
    (void)buf;
    (void)len;
    return 0;
}

#endif // MOCK_DPDK_H
