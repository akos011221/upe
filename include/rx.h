#ifndef RX_H
#define RX_H

#include <stddef.h>
#include <stdint.h>

#include "pktbuf.h"
#include "ring.h"
#include "rule_table.h"

typedef struct {
    const char *iface;
    const char *pcap_file;

    pktbuf_pool_t *pool;

    spsc_ring_t *rings;
    uint16_t ring_count;
} rx_ctx_t;

int rx_start(rx_ctx_t *rx);
void rx_stop(void);

#endif