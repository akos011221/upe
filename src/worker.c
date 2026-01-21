#define _POSIX_C_SOURCE 200809L
#include "worker.h"
#include "arp_table.h"
#include "log.h"
#include "parser.h"

#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Global stop flag from main; required for all workers.
extern volatile sig_atomic_t g_stop;

static void *worker_main(void *arg) {
    worker_t *w = (worker_t *)arg;

    while (1) {
        pktbuf_t *b = (pktbuf_t *)ring_pop(w->rx_ring);
        if (!b) {
            if (g_stop) {
                // Stop signal received + ring is empty.
                break;
            } else {
                // Ring empty => avoid burning CPU while doing nothing.
                struct timespec ts = {.tv_sec = 0, .tv_nsec = 1000000}; // 1ms
                nanosleep(&ts, NULL);
                continue;
            }
        }

        w->pkts_in++;

        // Debug: Visualize the raw packet data
        log_hexdump(LOG_DEBUG, b->data, b->len);

        // Parse the flow
        flow_key_t key;
        if (parse_flow_key(b->data, b->len, &key) != 0) {
            // Not a valid IPv4/TCP/UDP, drop it.
            w->pkts_dropped++;
            pktbuf_free(w->pool, b);
            continue;
        }
        w->pkts_parsed++;

        // Match a rule
        const rule_t *r = rule_table_match(w->rt, &key);
        if (!r) {
            // No match, drop it.
            w->pkts_dropped++;
            pktbuf_free(w->pool, b);
            continue;
        }
        w->pkts_matched++;

        // Update per-rule counters. Lock-free as it's a private array for each worker.
        if (w->rule_stats) {
            w->rule_stats[r->rule_id].packets++;
            w->rule_stats[r->rule_id].bytes += b->len;
        }

        if (r->action.type == ACT_DROP) {
            w->pkts_dropped++;
            pktbuf_free(w->pool, b);
            continue;
        }

        if (r->action.type == ACT_FWD) {
            /*
                [L3 Processing]
                    For IPv4, decrement TTL and update checksum.
                    Then do ARP lookup and rewrite the DstMac.
                        Otherwise: transparent bridge.
            */
            struct eth_hdr *eth = (struct eth_hdr *)b->data;

            if (key.ip_ver == 4) {
                struct ipv4_hdr *ip = (struct ipv4_hdr *)(b->data + sizeof(struct eth_hdr));

                if (ip->ttl <= 1) {
                    w->pkts_dropped++;
                    pktbuf_free(w->pool, b);
                    continue;
                }

                ip->ttl--;
                ip->checksum = 0; // Must be 0 before calculation.
                ip->checksum = ipv4_checksum(ip, (ip->ver_ihl & 0x0F) * 4);

                uint8_t dst_mac[6];
                if (arp_get_mac(key.dst_ip.v4, dst_mac)) {
                    memcpy(eth->dst, dst_mac, 6);
                }
            }

            // Forward out on TX interface the raw L2 frame (as captured).
            if (tx_send(w->tx, b->data, b->len) != 0) {
                w->pkts_forwarded++;
            } else {
                // TX failed => can be considered dropped.
                w->pkts_dropped++;
            }

            pktbuf_free(w->pool, b);
            continue;
        }

        // Unknown action => drop it.
        w->pkts_dropped++;
        pktbuf_free(w->pool, b);
    }

    return NULL;
}

int worker_init(worker_t *w, int worker_id, spsc_ring_t *rx_ring, pktbuf_pool_t *pool,
                const rule_table_t *rt, const tx_ctx_t *tx) {
    if (!w || !rt) return -1;

    w->worker_id = worker_id;
    w->rx_ring = rx_ring;
    w->pool = pool;
    w->rt = rt;
    w->tx = tx;

    // Rule table capacity determines the size of the stats array.
    w->rule_stats = (rule_stat_t *)calloc(rt->capacity, sizeof(rule_stat_t));
    if (!w->rule_stats) return -1;

    return 0;
}

void worker_destroy(worker_t *w) {
    if (w && w->rule_stats) free(w->rule_stats);
}

int worker_start(worker_t *w) {
    if (!w) return -1;
    return pthread_create(&w->thread, NULL, worker_main, w);
}

void worker_join(worker_t *w) {
    if (!w) return;
    pthread_join(w->thread, NULL);
}