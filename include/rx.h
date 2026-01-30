#ifndef RX_H
#define RX_H

#include <stddef.h>
#include <stdint.h>

#include "pktbuf.h"
#include "ring.h"
#include "rule_table.h"

#define RX_BURST_SIZE 32

typedef struct {
    pktbuf_t *buffer[RX_BURST_SIZE];
    unsigned int count;
} rx_batch_t;

typedef struct {
    const char *iface;
    const char *pcap_file;

    pktbuf_pool_t *pool;

    spsc_ring_t *rings;
    uint16_t ring_count;
    rx_batch_t *batches;
} rx_ctx_t;

int rx_start(rx_ctx_t *rx);
void rx_stop(void);

#endif