#ifndef WORKER_H
#define WORKER_H

#include <pthread.h>
#include <stdint.h>

#include "arp_table.h"
#include "ndp_table.h"
#include "pktbuf.h"
#include "ring.h"
#include "rule_table.h"
#include "tx.h"

typedef struct {
    uint64_t packets;
    uint64_t bytes;
} rule_stat_t;

typedef struct {
    int worker_id;

    spsc_ring_t *rx_ring;
    pktbuf_pool_t *pool;

    const rule_table_t *rt;
    const tx_ctx_t *tx;
    arp_table_t *arpt;
    ndp_table_t *ndpt;

    // Per-rule statistics, indexed by rule_id. size=rt->capacity.
    rule_stat_t *rule_stats;

    // Per-worker counters
    uint64_t pkts_in;
    uint64_t pkts_parsed;
    uint64_t pkts_matched;
    uint64_t pkts_forwarded;
    uint64_t pkts_dropped;

    // L1 ARP Cache (1st level before looking into the ARP table)
    uint32_t last_arp_ip;
    uint8_t last_arp_mac[6];

    // L1 NDP Cache (1st level before looking into the NDP table)
    uint8_t last_ndp_ip[16];
    uint8_t last_ndp_mac[6];

    pthread_t thread;
} worker_t;

/* Initialize worker, allocate stats memory for it. */
int worker_init(worker_t *w, int worker_id, spsc_ring_t *rx_ring, pktbuf_pool_t *pool,
                const rule_table_t *rt, const tx_ctx_t *tx, arp_table_t *arpt, ndp_table_t *ndpt);
/* Free worker memory. */
void worker_destroy(worker_t *w);

int worker_start(worker_t *w);
void worker_join(worker_t *w);

#endif