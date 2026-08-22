#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_byteorder.h>
#include <string.h>
#include <unistd.h>

#include "latency.h"
#include "log.h"
#include "mac_table.h"
#include "router.h"
#include "arp4.h"
#include "lpm.h"

/* Get pointer to the Ethernet header inside an mbuf. */
static inline struct rte_ether_hdr *eth_hdr(struct rte_mbuf *mbuf) {
    return rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
}

/* Flush TX buffers for a certain port. Qued packets will be sent,
 * unsent ones will be freed. */
static inline void flush_tx_buffer(uint16_t port_id, tx_buffer_t *buf) {
    if (buf->count == 0) return;

    uint16_t sent = rte_eth_tx_burst(port_id, 0, buf->mbufs, buf->count);

    /* If the NIC didn't accept some, free those. */
    for (uint16_t i = sent; i < buf->count; i++)
        rte_pktmbuf_free(buf->mbufs[i]);

    buf->count = 0;
}

/* Enqueue a mbuf into TX buffer, flush if it's full. */
static inline void enqueue_tx(uint16_t port_id, tx_buffer_t *buf, struct rte_mbuf *mbuf) {
    buf->mbufs[buf->count++] = mbuf;

    if (buf->count == BURST_SIZE) flush_tx_buffer(port_id, buf);
}

/* Generate and send ARP request with existing mbuf. */
static void send_arp_request(rx_lcore_ctx_t *ctx, struct rte_mbuf *mbuf, uint16_t egress_port,
                             uint32_t target_ip) {
    /* Reuse the mbuf: overwrite with ARP request. */
    uint16_t pkt_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    mbuf->data_len = pkt_len;
    mbuf->pkt_len = pkt_len;

    struct rte_ether_hdr *eth = eth_hdr(mbuf);
    struct rte_arp_hdr *arp = rte_pktmbuf_mtod_offset(mbuf, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

    /* Ethernet hdr */
    memset(&eth->dst_addr, 0xFF, 6); /* Broadcast */
    rte_ether_addr_copy((const struct rte_ether_addr *)ctx->ifaces[egress_port].mac, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    /* ARP hdr */
    arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = 6;
    arp->arp_plen = 4;
    arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);

    rte_ether_addr_copy((const struct rte_ether_addr *)ctx->ifaces[egress_port].mac, &arp->arp_data.arp_sha);
    arp->arp_data.arp_sip = ctx->ifaces[egress_port].ip;
    memset(&arp->arp_data.arp_tha, 0, 6);
    arp->arp_data.arp_tip = target_ip;

    enqueue_tx(egress_port, &ctx->tx_buffers[egress_port], mbuf);
}

/* Handle ARP packets (requests, replies). */
static bool handle_arp(rx_lcore_ctx_t *ctx, struct rte_mbuf *mbuf, uint16_t ingress_port, uint64_t ingress_tsc) {
    if (!ctx->ifaces[ingress_port].configured) return false;

    struct rte_ether_hdr *eth = eth_hdr(mbuf);
    struct rte_arp_hdr *arp = rte_pktmbuf_mtod_offset(mbuf, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

    if (rte_be_to_cpu_16(arp->arp_hardware) != RTE_ARP_HRD_ETHER ||
        rte_be_to_cpu_16(arp->arp_protocol) != RTE_ETHER_TYPE_IPV4 ||
        arp->arp_hlen != 6 || arp->arp_plen != 4) {
        return false;
    }

    uint32_t tip = arp->arp_data.arp_tip;
    uint32_t sip = arp->arp_data.arp_sip;
    uint32_t my_ip = ctx->ifaces[ingress_port].ip;
    uint16_t op = rte_be_to_cpu_16(arp->arp_opcode);

    if (op == RTE_ARP_OP_REQUEST) {
        if (tip == my_ip) {
            rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
            rte_ether_addr_copy((const struct rte_ether_addr *)ctx->ifaces[ingress_port].mac, &eth->src_addr);

            arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

            rte_ether_addr_copy(&arp->arp_data.arp_sha, &arp->arp_data.arp_tha);
            arp->arp_data.arp_tip = arp->arp_data.arp_sip;

            rte_ether_addr_copy((const struct rte_ether_addr *)ctx->ifaces[ingress_port].mac, &arp->arp_data.arp_sha);
            arp->arp_data.arp_sip = my_ip;

            /* Learn the sender's MAC, IP. */
            arp4_insert(&ctx->arp4, sip, arp->arp_data.arp_tha.addr_bytes);

            uint64_t egress_tsc = rdtsc();
            latency_record(&ctx->latency_hist[ingress_port], egress_tsc - ingress_tsc, ctx->cycles_per_ns);
            enqueue_tx(ingress_port, &ctx->tx_buffers[ingress_port], mbuf);

            return true;
        }
    } else if (op == RTE_ARP_OP_REPLY) {
        if (tip == my_ip) {
            /* Received a reply to my request. */
            arp4_insert(&ctx->arp4, sip, arp->arp_data.arp_sha.addr_bytes);
            rte_pktmbuf_free(mbuf);
            return true;
        }
    }

    return false;
}

/* Handle ICMP Echo Requests to the router. */
static bool handle_icmp_echo(rx_lcore_ctx_t *ctx, struct rte_mbuf *mbuf, uint16_t ingress_port, uint64_t ingress_tsc) {
    struct rte_ether_hdr *eth = eth_hdr(mbuf);
    struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

    uint16_t ihl_bytes = (ipv4->version_ihl & 0x0f) * 4;
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)((uint8_t *)ipv4 + ihl_bytes);

    if (icmp->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
        /* Swap MACs */
        rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
        rte_ether_addr_copy((const struct rte_ether_addr *)ctx->ifaces[ingress_port].mac, &eth->src_addr);

        /* Swap IPs */
        uint32_t tmp_ip = ipv4->src_addr;
        ipv4->src_addr = ipv4->dst_addr;
        ipv4->dst_addr = tmp_ip;

        /* Update to ICMP Reply */
        icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;

        /* Incrementally update ICMP checksum (Type changed from 8 to 0) */
        uint32_t cksum = ~icmp->icmp_cksum & 0xFFFF;
        cksum += rte_cpu_to_be_16(0x0800);
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
        icmp->icmp_cksum = ~cksum & 0xFFFF;

        uint64_t egress_tsc = rdtsc();
        latency_record(&ctx->latency_hist[ingress_port], egress_tsc - ingress_tsc, ctx->cycles_per_ns);
        enqueue_tx(ingress_port, &ctx->tx_buffers[ingress_port], mbuf);

        return true;
    }

    return false;
}

/* Handle IPv4 packets */
static bool handle_ipv4(rx_lcore_ctx_t *ctx, struct rte_mbuf *mbuf, uint16_t ingress_port, uint64_t ingress_tsc) {
    if (!ctx->ifaces[ingress_port].configured) return false;

    struct rte_ether_hdr *eth = eth_hdr(mbuf);
    struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

    uint32_t dst_ip = ipv4->dst_addr;

    /* Local Delivery Check */
    for (uint16_t i = 0; i < MAX_PORTS; i++) {
        if (ctx->ifaces[i].configured && ctx->ifaces[i].ip == dst_ip) {
            ctx->packets_local++;
           
            /* Responding to ICMP */
            if (ipv4->next_proto_id == IPPROTO_ICMP) {
                if (handle_icmp_echo(ctx, mbuf, ingress_port, ingress_tsc)) {
                    return true;
                }
            }

            rte_pktmbuf_free(mbuf); /* Drop other traffic for local stack */
            return true;
        }
    }

    /* TTL Check */
    if (ipv4->time_to_live <= 1) {
        ctx->packets_ttl_exceeded++;
        rte_pktmbuf_free(mbuf); // TODO: Send ICMP Time Exceeded.
        return true;
    }

    /* Route Lookup */
    uint32_t next_hop_ip;
    uint16_t egress_port;
    if (!lpm_lookup(&ctx->lpm, dst_ip, &next_hop_ip, &egress_port)) {
        ctx->packets_no_route++;
        rte_pktmbuf_free(mbuf); // TODO: Send ICMP Dest Unreachable.
        return true;
    }

    if (next_hop_ip == 0) {
        /* Directly connected network. */
        next_hop_ip = dst_ip;
    }

    /* ARP Lookup */
    uint8_t next_hop_mac[6];
    if (!arp4_lookup(&ctx->arp4, next_hop_ip, next_hop_mac)) {
        /* ARP Miss: Drop the IP packet and reuse the mbuf to send
         * an ARP request out of egress_port. */
        ctx->packets_arp_miss++;
        send_arp_request(ctx, mbuf, egress_port, next_hop_ip);
        return true;
    }

    /* IPv4 Header Rewrite */
    ipv4->time_to_live--;
    ipv4->hdr_checksum = 0;
    ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);

    rte_ether_addr_copy((const struct rte_ether_addr *)ctx->ifaces[egress_port].mac, &eth->src_addr);
    rte_ether_addr_copy((const struct rte_ether_addr *)next_hop_mac, &eth->dst_addr);

    uint64_t egress_tsc = rdtsc();
    latency_record(&ctx->latency_hist[ingress_port], egress_tsc - ingress_tsc, ctx->cycles_per_ns);
    enqueue_tx(egress_port, &ctx->tx_buffers[egress_port], mbuf);

    ctx->packets_routed++;
    ctx->bytes_forwarded += mbuf->pkt_len;

    return true;
}

/* Forward or flood one mbuf received on ingress_port. */
static void forward_mbuf(rx_lcore_ctx_t *ctx, struct rte_mbuf *mbuf, uint16_t ingress_port,
                         uint64_t ingress_tsc) {
    struct rte_ether_hdr *hdr = eth_hdr(mbuf);
    const uint8_t *src_mac = hdr->src_addr.addr_bytes;
    const uint8_t *dst_mac = hdr->dst_addr.addr_bytes;

    /* MAC learning of unicast source MACs. */
    if (mac_is_unicast(src_mac)) {
        mac_table_insert(&ctx->mac_table, src_mac, ingress_port, ingress_tsc);
    }

    /* L3 Classification. */
    bool is_broadcast = mac_is_broadcast(dst_mac);
    bool for_us = is_broadcast;

    if (!for_us && ctx->ifaces[ingress_port].configured) {
        if (memcmp(dst_mac, ctx->ifaces[ingress_port].mac, 6) == 0) {
            for_us = true;
        }
    }

    if (for_us) {
        uint16_t eth_type = rte_be_to_cpu_16(hdr->ether_type);
        bool consumed = false;

        if (eth_type == RTE_ETHER_TYPE_ARP) {
            consumed = handle_arp(ctx, mbuf, ingress_port, ingress_tsc);
        } else if (eth_type == RTE_ETHER_TYPE_IPV4 && !is_broadcast) {
            consumed = handle_ipv4(ctx, mbuf, ingress_port, ingress_tsc);
        }

        if (consumed) return;

        /* Unicast meant for us, but unknown Ethertype. */
        if (!is_broadcast && memcmp(dst_mac, ctx->ifaces[ingress_port].mac, 6) == 0) {
            rte_pktmbuf_free(mbuf);
            ctx->packets_dropped++;
            return;
        }

        /* If it's broadcast (DHCP, LLDP...) and not consumed, 
         * fall through to L2 flooding. */
    }

    /* Forwarding decision (L2 Fallback). */
    bool should_flood = mac_is_broadcast(dst_mac) || !mac_is_unicast(dst_mac);

    uint16_t egress_port = 0;
    if (!should_flood) {
        /* Try unicast lookup */
        if (!mac_table_lookup(&ctx->mac_table, dst_mac, ingress_tsc, &egress_port)) {
            should_flood = true; /* Unknown dst. */
        }
    }

    if (!should_flood) {
        if (egress_port == ingress_port) {
            rte_pktmbuf_free(mbuf);
            ctx->packets_dropped++;
        } else {
            uint64_t egress_tsc = rdtsc();
            latency_record(&ctx->latency_hist[ingress_port], egress_tsc - ingress_tsc,
                           ctx->cycles_per_ns);
            enqueue_tx(egress_port, &ctx->tx_buffers[egress_port], mbuf);
            ctx->packets_forwarded++;
            ctx->bytes_forwarded += mbuf->pkt_len;
        }
    } else { /* Flood to all ports except ingress. */
        struct rte_mbuf *copies[MAX_PORTS];
        uint16_t egress_ports[MAX_PORTS];
        uint16_t n_egress = 0;

        uint64_t active_ports = __atomic_load_n(&ctx->active_ports_mask,
                                                __ATOMIC_ACQUIRE);

        for (uint16_t p = 0; p < MAX_PORTS; p++) {
            /* Port's bit should be 1 and not ingress port. */
            if ((active_ports & (1ULL << p)) && (p != ingress_port)) {
                egress_ports[n_egress++] = p;
            }
        }

        /* Allocate clones for the egress port. */
        bool alloc_ok = true;
        copies[0] = mbuf; /* First egress gets the original pointer. */

        for (uint16_t i = 1; i < n_egress; i++) {
            copies[i] = rte_pktmbuf_clone(mbuf, mbuf->pool);
            if (copies[i] == NULL) {
                log_msg(LOG_WARN, "Pool exhausted during flood clone");
                ctx->pool_exhaustion_count++;
                log_msg(LOG_WARN, "Pool exhaustion count: %lu", ctx->pool_exhaustion_count);

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
                latency_record(&ctx->latency_hist[ingress_port], egress_tsc - ingress_tsc,
                               ctx->cycles_per_ns);
                enqueue_tx(egress_ports[i], &ctx->tx_buffers[egress_ports[i]], copies[i]);
            }
            ctx->packets_flooded++;
            ctx->bytes_forwarded += mbuf->pkt_len;
        }
    }
}

int rx_lcore_main(void *arg) {
    rx_lcore_ctx_t *ctx = (rx_lcore_ctx_t *)arg;

    log_msg(LOG_INFO, "RX lcore %u started", rte_lcore_id());

    struct rte_mbuf *rx_mbufs[BURST_SIZE];

    uint64_t idle_count = 0;
    const uint64_t IDLE_THRESHOLD = 10000;

    while (!ctx->stop) {
        uint64_t active_ports = __atomic_load_n(&ctx->active_ports_mask,
                                                __ATOMIC_ACQUIRE);
        bool traffic_exceeds_threshold = false;

        for (uint16_t p = 0; p < MAX_PORTS; p++) {
            if (!(active_ports & (1ULL << p))) continue;

            uint16_t nb_rx = rte_eth_rx_burst(p, 0, rx_mbufs, BURST_SIZE);

            if (nb_rx > 0) {
                uint64_t ingress_tsc = rdtsc();

                for (uint16_t i = 0; i < nb_rx; i++) {
                    if (ctx->adaptive_sleep && rx_mbufs[i]->pkt_len > ctx->sleep_threshold) {
                        traffic_exceeds_threshold = true;
                    }
                    forward_mbuf(ctx, rx_mbufs[i], p, ingress_tsc);
                }
            }
        }

        /* Flush happens at every pass. */
        for (uint16_t p = 0; p < MAX_PORTS; p++) {
            if (active_ports & (1ULL << p)) {
                flush_tx_buffer(p, &ctx->tx_buffers[p]);
            }
        }

        if (ctx->adaptive_sleep) {
            if (!traffic_exceeds_threshold) {
                idle_count++;
                if (idle_count > IDLE_THRESHOLD) {
                    usleep(10);
                }
            } else {
                idle_count = 0;
            }
        }
    }

    log_msg(LOG_INFO, "RX lcore %u stopping, will flush TX buffers...", rte_lcore_id());

    /* Final flush before shutdown. */
    uint64_t active_ports = __atomic_load_n(&ctx->active_ports_mask,
                                            __ATOMIC_ACQUIRE);
    for (uint16_t p = 0; p < MAX_PORTS; p++) {
        if (active_ports & (1ULL << p)) {
            flush_tx_buffer(p, &ctx->tx_buffers[p]);
        }
    }

    log_msg(LOG_INFO, "RX lcore %u stopped", rte_lcore_id());
    return 0;
}