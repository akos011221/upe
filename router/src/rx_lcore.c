#include <string.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

#include "router.h"
#include "mac_table.h"
#include "latency.h"
#include "log.h"

/* Get pointer to the Ethernet header inside an mbuf. */
static inline struct rte_ether_hdr *eth_hdr(struct rte_mbuf *mbuf) {
    return rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
}

/* Flush TX buffers for a certain port. Qued packets will be sent, 
 * unsent ones will be freed. */
static inline void flush_tx_buffer(uint16_t port_id, tx_buffer_t *buf) {
    if (buf->count == 0)
        return;

    uint16_t sent = rte_eth_tx_burst(port_id, 0, buf->mbufs, buf->count);

    /* If the NIC didn't accept some, free those. */
    for (uint16_t i = sent; i < buf->count; i++)
        rte_pktmbuf_free(buf->mbufs[i]);

    buf->count = 0;
}

/* Enqueue a mbuf into TX buffer, flush if it's full. */
static inline void enqueue_tx(uint16_t port_id, tx_buffer_t *buf,
                              struct rte_mbuf *mbuf) {
    buf->mbufs[buf->count++] = mbuf;

    if (buf->count == BURST_SIZE)
        flush_tx_buffer(port_id, buf);
}

/* Forward or flood one mbuf received on ingress_port. */
static void forward_mbuf(rx_lcore_ctx_t *ctx,
                         struct rte_mbuf *mbuf,
                         uint16_t ingress_port,
                         uint64_t ingress_tsc) {
    struct rte_ether_hdr *hdr = eth_hdr(mbuf);
    const uint8_t *src_mac = hdr->src_addr.addr_bytes;
    const uint8_t *dst_mac = hdr->dst_addr.addr_bytes;

    /* MAC learning of unicast source MACs. */
    if (mac_is_unicast(src_mac)) {
        mac_table_insert(&ctx->mac_table, src_mac,
                         ingress_port, ingress_tsc);
    }

    /* Forwarding decision. */
    bool should_flood = mac_is_broadcast(dst_mac) ||
                        !mac_is_unicast(dst_mac);
    
    uint16_t egress_port = 0;
    if (!should_flood) {
        /* Try unicast lookup */
        if (!mac_table_lookup(&ctx->mac_table, dst_mac,
                              ingress_tsc, &egress_port)) {
            should_flood = true; /* Unknown dst. */
        }
    }

    if (!should_flood) {
        if (egress_port == ingress_port) {
            rte_pktmbuf_free(mbuf);
            ctx->packets_dropped++;
        } else {
            uint64_t egress_tsc = rdtsc();
            latency_record(&ctx->latency_hist[ingress_port],
                           egress_tsc - ingress_tsc,
                           ctx->cycles_per_ns);
            enqueue_tx(egress_port, &ctx->tx_buffers[egress_port], mbuf);
            ctx->packets_forwarded++;
            ctx->bytes_forwarded += mbuf->pkt_len;
        }
    } else { /* Flood to all ports except ingress. */
        struct rte_mbuf *copies[NUM_PORTS];
        uint16_t egress_ports[NUM_PORTS];
        uint16_t n_egress = 0;

        for (uint16_t p = 0; p < NUM_PORTS; p++) {
            if (p != ingress_port)
                egress_ports[n_egress++] = p;
        }

        /* Allocate copies for the egress port. */
        bool alloc_ok = true;
        copies[0] = mbuf; /* First egress gets the original. */

        for (uint16_t i = 1; i < n_egress; i++) {
            copies[i] = rte_pktmbuf_copy(mbuf, mbuf->pool, 0, UINT32_MAX);
            if (copies[i] == NULL) {
                log_msg(LOG_WARN, "Pool exhausted during flood copy");
                ctx->pool_exhaustion_count++;
                log_msg(LOG_WARN, "Pool exhaustion count: %lu",
                        ctx->pool_exhaustion_count);
                
                rte_pktmbuf_free(mbuf);
                for (uint16_t j = 1; j < i; j++)
                    rte_pktmbuf_free(copies[j]);
                alloc_ok = false;
                break;
            }
        }

        if (alloc_ok) {
            for (uint16_t i = 0; i < n_egress; i++) {
                uint64_t egress_tsc = rdtsc();
                latency_record(&ctx->latency_hist[ingress_port],
                               egress_tsc - ingress_tsc,
                               ctx->cycles_per_ns);
                enqueue_tx(egress_ports[i],
                           &ctx->tx_buffers[egress_ports[i]],
                           copies[i]);
            }
            ctx->packets_flooded++;
            ctx->bytes_forwarded += mbuf->pkt_len;
        }
    }
}