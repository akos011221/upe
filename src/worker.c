#define _POSIX_C_SOURCE 200809L
#include "worker.h"
#include "arp_table.h"
#include "log.h"
#include "ndp_table.h"
#include "parser.h"

#include <arpa/inet.h>
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

        struct eth_hdr *eth = (struct eth_hdr *)b->data;

        // Check for ARP packets
        if (ntohs(eth->ethertype) == 0x0806) {
            if (b->len >= sizeof(struct eth_hdr) + sizeof(struct arp_hdr)) {
                struct arp_hdr *arp = (struct arp_hdr *)(b->data + sizeof(struct eth_hdr));

                // Hardware Type 1 (Ethernet), Protocol 0x0800 (IPv4), HW Len 6, Proto Len 4
                if (ntohs(arp->htype) == 1 && ntohs(arp->ptype) == 0x0800 && arp->hlen == 6 &&
                    arp->plen == 4) {
                    uint32_t spa = ntohl(arp->spa); // Sender Protocol Address (IP)
                    arp_update(w->arpt, spa, arp->sha);
                    log_msg(LOG_DEBUG, "Learned ARP: %08X -> %02X:%02X:%02X:%02X:%02X:%02X", spa,
                            arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4],
                            arp->sha[5]);
                }
            }
            /* Consume the packet */
            pktbuf_free(w->pool, b);
            continue;
        }

        // Check for IPv6 NDP packet (Neighbor Advertisement)
        if (ntohs(eth->ethertype) == 0x86DD) {
            if (b->len >=
                sizeof(struct eth_hdr) + sizeof(struct ipv6_hdr) + sizeof(struct ndp_na_hdr)) {
                struct ipv6_hdr *ip6 = (struct ipv6_hdr *)(b->data + sizeof(struct eth_hdr));

                // Next Header 58: ICMPv6
                if (ip6->next_header == 58) {
                    struct ndp_na_hdr *ndp =
                        (struct ndp_na_hdr *)(b->data + sizeof(struct eth_hdr) +
                                              sizeof(struct ipv6_hdr));

                    // Type 135: Neighbor Solicitation (Learn from Source LL Addr)
                    // Type 136: Neighbor Advertisement (Learn from Target LL Addr)
                    if (ndp->type == 135 || ndp->type == 136) {
                        // Parsing Options will reveal target Link-Layer Address
                        size_t offset = sizeof(struct eth_hdr) + sizeof(struct ipv6_hdr) +
                                        sizeof(struct ndp_na_hdr);

                        while (offset + 2 <= b->len) {
                            uint8_t opt_type = b->data[offset];
                            uint8_t opt_len = b->data[offset + 1] * 8; // Length: units of 8 octets

                            if (opt_len == 0 || offset + opt_len > b->len)
                                break; /* Invalid packet */

                            // NS (135) -> Look for Type 1 (Source LL) -> Map IPv6 Src to MAC
                            if (ndp->type == 135 && opt_type == 1 && opt_len >= 8) {
                                uint8_t *mac = b->data + offset + 2;
                                ndp_update(w->ndpt, ip6->src_addr, mac);
                                log_msg(LOG_DEBUG,
                                        "Learned NDP (NS): %02x:%02x:%02x:%02x:%02x:%02x", mac[0],
                                        mac[1], mac[2], mac[3], mac[4], mac[5]);
                                break;
                            }

                            // NA (136) -> Look for Type 2 (Target LL) -> Map IPv6 Dst to MAC
                            if (ndp->type == 136 && opt_type == 2 && opt_len >= 8) {
                                uint8_t *mac = b->data + offset + 2;
                                ndp_update(w->ndpt, ndp->target, mac);
                                log_msg(LOG_DEBUG,
                                        "Learned NDP (NA): %02x:%02x:%02x:%02x:%02x:%02x", mac[0],
                                        mac[1], mac[2], mac[3], mac[4], mac[5]);
                                break;
                            }
                            offset += opt_len;
                        }
                        /* Consume the packet */
                        pktbuf_free(w->pool, b);
                        continue;
                    }
                }
            }
        }

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
                    Then do ARP lookup and rewrite Src, Dst MAC
                        Otherwise: transparent bridge.
            */
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
                bool found = false;

                /*
                    First, check the local cache (1 element) to avoid lock contention.
                        If packet is going to the same DstIP as the previous one, re-use the MAC.
                            This way we don't have to use the lock.
                */
                if (w->last_arp_ip != 0 && key.dst_ip.v4 == w->last_arp_ip) {
                    memcpy(dst_mac, w->last_arp_mac, 6);
                    found = true;
                } else if (arp_get_mac(w->arpt, key.dst_ip.v4, dst_mac)) {
                    // If not in the cache, must do the look up & also update the worker cache.
                    w->last_arp_ip = key.dst_ip.v4;
                    memcpy(w->last_arp_mac, dst_mac, 6);
                    found = true;
                }

                if (found) {
                    memcpy(eth->dst, dst_mac, 6);
                    memcpy(eth->src, w->tx->eth_addr, 6);
                }
            } else if (key.ip_ver == 6) {
                struct ipv6_hdr *ip6 = (struct ipv6_hdr *)(b->data + sizeof(struct eth_hdr));

                if (ip6->hop_limit <= 1) {
                    w->pkts_dropped++;
                    pktbuf_free(w->pool, b);
                    continue;
                }

                ip6->hop_limit--;

                uint8_t dst_mac[6];
                bool found = false;

                if (memcmp(key.dst_ip.v6, w->last_ndp_ip, 16) == 0) {
                    memcpy(dst_mac, w->last_ndp_mac, 6);
                    found = true;
                } else if (ndp_get_mac(w->ndpt, key.dst_ip.v6, dst_mac)) {
                    memcpy(w->last_ndp_ip, key.dst_ip.v6, 16);
                    memcpy(w->last_ndp_mac, dst_mac, 6);
                    found = true;
                }

                if (found) {
                    memcpy(eth->dst, dst_mac, 6);
                    memcpy(eth->src, w->tx->eth_addr, 6);
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
                const rule_table_t *rt, const tx_ctx_t *tx, arp_table_t *arpt, ndp_table_t *ndpt) {
    if (!w || !rt) return -1;

    w->worker_id = worker_id;
    w->rx_ring = rx_ring;
    w->pool = pool;
    w->rt = rt;
    w->tx = tx;
    w->arpt = arpt;
    w->ndpt = ndpt;

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