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
    // Thread metadata [cold, accessed once at startup]
    pthread_t thread;
    int worker_id;

    // Pointers [cold, dereferenced but the pointer itself rarely changes]
    spsc_ring_t *rx_ring;
    pktbuf_pool_t *pool;
    const rule_table_t *rt;
    const tx_ctx_t *tx;
    arp_table_t *arpt;
    ndp_table_t *ndpt;

    // Per-worker counters [hot, accessed for every packet]
    uint64_t pkts_in;
    uint64_t pkts_parsed;
    uint64_t pkts_matched;
    uint64_t pkts_forwarded;
    uint64_t pkts_dropped;

    // Per-rule statistics [warm, accessed per matched packet]
    // ... indexed by rule_id. size=rt->capacity.
    rule_stat_t *rule_stats;

    // L1 ARP Cache (1st level before looking into the ARP table)
    // [warm, accessed per forwarded packet]
    uint32_t last_arp_ip;
    uint8_t last_arp_mac[6];

    // L1 NDP Cache (1st level before looking into the NDP table)
    // [warm, accessed per forwarded packet]
    uint8_t last_ndp_ip[16];
    uint8_t last_ndp_mac[6];

    // CPU core assigned to this worker [cold, accessed once at startup]
    int core_id;
} worker_t;

/* Initialize worker, allocate stats memory for it. */
int worker_init(worker_t *w, int worker_id, int core_id, spsc_ring_t *rx_ring, pktbuf_pool_t *pool,
                const rule_table_t *rt, const tx_ctx_t *tx, arp_table_t *arpt, ndp_table_t *ndpt);
/* Free worker memory. */
void worker_destroy(worker_t *w);

int worker_start(worker_t *w);
void worker_join(worker_t *w);

#endif