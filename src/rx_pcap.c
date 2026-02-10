#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#include "log.h"
#include "parser.h"
#include "rx.h"

#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>

static pcap_t *g_pcap = NULL;

void rx_stop(void) {
    if (g_pcap) pcap_breakloop(g_pcap);
}

// Round robin distribution of packets across the rings.
static uint32_t pick_ring_round_robin(uint32_t ring_count) {
    static uint32_t rr = 0; // static, so keeps its value between function calls
    uint32_t idx = rr;
    rr = (rr + 1) & (ring_count - 1);
    return idx;
}

// Flush pending packets in the staging buffers to the rings.
static void flush_rx_buffers(rx_ctx_t *rx) {
    for (uint32_t i = 0; i < rx->ring_count; i++) {
        if (rx->batches[i].count > 0) {
            unsigned int pushed = ring_push_burst(&rx->rings[i], (void **)rx->batches[i].buffer,
                                                  rx->batches[i].count);
            // If ring is full: drop the remaining packets
            for (unsigned int k = pushed; k < rx->batches[i].count; k++) {
                pktbuf_free(rx->pool, rx->batches[i].buffer[k]);
            }
            rx->batches[i].count = 0;
        }
    }
}

static void pcap_callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes) {
    rx_ctx_t *rx = (rx_ctx_t *)user;

    // Allocate an own buffer.
    pktbuf_t *b = pktbuf_alloc(rx->pool);
    if (!b) {
        // Pool is full, drop the packet.
        return;
    }

    // Make sure packet fits in the buffer.
    if (hdr->caplen > PKTBUF_DATA_SIZE) {
        // Oversized packet, drop it.
        pktbuf_free(rx->pool, b);
        return;
    }

    // Copy the bytes into the owned buffer.
    memcpy(b->data, bytes, hdr->caplen);
    b->len = hdr->caplen;

    // Choose a worker ring based on Flow Hash (Software RSS).
    flow_key_t k;
    uint32_t ring_id;

    if (parse_flow_key(b->data, b->len, &k) == 0) {
        uint32_t hash = flow_hash(&k);
        ring_id = hash & (rx->ring_count - 1);
    } else {
        // Fallback to Round Robin for non-IP/malformed packets.
        ring_id = pick_ring_round_robin(rx->ring_count);
    }

    // Add to local batch buffer
    rx->batches[ring_id].buffer[rx->batches[ring_id].count++] = b;

    if (rx->batches[ring_id].count == RX_BURST_SIZE) {
        // Buffer is full, time to flush now
        unsigned int pushed = ring_push_burst(&rx->rings[ring_id],
                                              (void **)rx->batches[ring_id].buffer, RX_BURST_SIZE);

        // Free buffers that didn't fit (drop them)
        for (unsigned int i = pushed; i < RX_BURST_SIZE; i++) {
            pktbuf_free(rx->pool, rx->batches[ring_id].buffer[i]);
        }
        rx->batches[ring_id].count = 0;
    }
}

int rx_start(rx_ctx_t *rx) {
    if (!rx || !rx->pool || !rx->rings || rx->ring_count == 0) return -1;

    if ((rx->ring_count & (rx->ring_count - 1)) != 0) {
        log_msg(LOG_ERROR, "rx->ring_count (%d) must be power of two", rx->ring_count);
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    if (rx->pcap_file) {
        g_pcap = pcap_open_offline(rx->pcap_file, errbuf);
        if (!g_pcap) {
            log_msg(LOG_ERROR, "pcap_open_offline failed: %s", errbuf);
            return -1;
        }
        log_msg(LOG_INFO, "RX started on file %s", rx->pcap_file);
    } else {
        if (!rx->iface) return -1;
        g_pcap = pcap_open_live(rx->iface, 65536, 1, 1, errbuf);
        if (!g_pcap) {
            log_msg(LOG_ERROR, "pcap_open_live failed: %s", errbuf);
            return -1;
        }
        log_msg(LOG_INFO, "RX started on %s (libpcap)", rx->iface);

        // Loopback prevention to avoid reading outgoing packets
        if (pcap_setdirection(g_pcap, PCAP_D_IN) < 0) {
            log_msg(LOG_WARN, "pcap_setdirection failed: %s", pcap_geterr(g_pcap));
        }
    }

    rx->batches = calloc(rx->ring_count, sizeof(rx_batch_t));
    if (!rx->batches) {
        log_msg(LOG_ERROR, "calloc failed for rx->batches");
        return -1;
    }

    // pcap_dispatch is to allow periodic flushing of partial batches
    while (1) {
        // Process batch of packets from the OS
        /*
            pcap_dispatch operates on the `pcap_t` handle, that encapsulates the config
            set during `pcap_open_live`.
                - the 4rd argument of `pcap_open_live` is to_ms, which is "1"
            `pcap_dispatch` times out after 1ms, returning 0.
        */
        int rc = pcap_dispatch(g_pcap, RX_BURST_SIZE, pcap_callback, (u_char *)rx);

        if (rc < 0) {
            if (rc == -2) break; // pcap_breakloop called
            log_msg(LOG_ERROR, "pcap_dispatch failed: %s", pcap_geterr(g_pcap));
            break;
        }

        // Flush packets that are sitting in the staging buffers
        // It's guaranteed to run at least once every milisecond (1ms timeout coming from
        // pcap_open_live)
        flush_rx_buffers(rx);
    }

    pcap_close(g_pcap);
    g_pcap = NULL;
    free(rx->batches);
    rx->batches = NULL;
    return 0;
}