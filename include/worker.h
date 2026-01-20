#ifndef WORKER_H
#define WORKER_H

#include <pthread.h>
#include <stdint.h>

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

    // Per-rule statistics, indexed by rule_id. size=rt->capacity.
    rule_stat_t *rule_stats;

    // Per-worker counters
    uint64_t pkts_in;
    uint64_t pkts_parsed;
    uint64_t pkts_matched;
    uint64_t pkts_forwarded;
    uint64_t pkts_dropped;

    pthread_t thread;
} worker_t;

/* Initialize worker, allocate stats memory for it. */
int worker_init(worker_t *w, int worker_id, spsc_ring_t *rx_ring, pktbuf_pool_t *pool,
                const rule_table_t *rt, const tx_ctx_t *tx);
/* Free worker memory. */
void worker_destroy(worker_t *w);

int worker_start(worker_t *w);
void worker_join(worker_t *w);

#endif