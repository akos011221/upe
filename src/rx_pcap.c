#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#include "log.h"
#include "parser.h"
#include "rx.h"

#include <arpa/inet.h>
#include <errno.h>
#include <pcap/pcap.h>
#include <stdio.h>
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
    rr = (rr + 1) % ring_count;
    return idx;
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
        ring_id = hash % rx->ring_count;
    } else {
        // Fallback to Round Robin for non-IP/malformed packets.
        ring_id = pick_ring_round_robin(rx->ring_count);
    }

    // Push the packet into the ring.
    if (!ring_push(&rx->rings[ring_id], b)) {
        // Ring is full, drop the packet.
        pktbuf_free(rx->pool, b);
        return;
    }
}

int rx_start(rx_ctx_t *rx) {
    if (!rx || !rx->pool || !rx->rings || rx->ring_count == 0) return -1;

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

    int rc = pcap_loop(g_pcap, -1, pcap_callback, (u_char *)rx);
    if (rc == -1) {
        log_msg(LOG_ERROR, "pcap_loop failed: %s", pcap_geterr(g_pcap));
        pcap_close(g_pcap);
        g_pcap = NULL;
        return -1;
    }

    log_msg(LOG_WARN, "pcap_loop exited rc=%d", rc);
    pcap_close(g_pcap);
    g_pcap = NULL;
    return 0;
}