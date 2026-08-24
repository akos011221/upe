#include "nat.h"
#include <arpa/inet.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_ring.h>
#include <rte_tcp.h>
#include <rte_udp.h>

struct nat_outbound_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    uint8_t padding[3];
};

struct nat_inbound_key {
    uint16_t wan_port;
    uint8_t proto;
    uint8_t padding;
};

static struct rte_hash *outbound_hash;
static struct rte_hash *inbound_hash;
static struct rte_ring *port_pool;
static uint32_t g_wan_ip;

void nat_init(uint32_t wan_ip) {
    g_wan_ip = wan_ip;

    port_pool = rte_ring_create("NAT_PORT_POOL", rte_align32pow2(NAT_MAX_ENTRIES), rte_socket_id(),
                                /* Allocate on the local CPU node's memory */ 0);
    if (!port_pool) {
        rte_exit(EXIT_FAILURE, "Failed to create NAT port pool\n");
    }

    /* Convert all 50K ports now at initialization time from
     * Little Endian to Big Endian.
     */
    for (uint16_t port = NAT_PORT_MIN; port < NAT_PORT_MAX; port++) {
        rte_ring_enqueue(port_pool, (void *)(uintptr_t)htons(port));
    }

    /* Outbound hash table. */
    struct rte_hash_parameters out_params = {.name = "NAT_OUTBOUND",
                                             .entries = NAT_MAX_ENTRIES,
                                             .key_len = sizeof(struct nat_outbound_key),
                                             .hash_func = rte_jhash,
                                             .hash_func_init_val = 0,
                                             .socket_id = rte_socket_id(),
                                             .extra_flag = 0};
    outbound_hash = rte_hash_create(&out_params);

    /* Inbound hash table. */
    struct rte_hash_parameters in_params = {.name = "NAT_INBOUND",
                                            .entries = NAT_MAX_ENTRIES,
                                            .key_len = sizeof(struct nat_inbound_key),
                                            .hash_func = rte_jhash,
                                            .hash_func_init_val = 0,
                                            .socket_id = rte_socket_id(),
                                            .extra_flag = 0};
    inbound_hash = rte_hash_create(&in_params);
}

void nat_outbound(struct rte_mbuf *m) {
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    /* Ignore non-IPv4 packets. */
    if (RTE_ETH_IS_IPV4_HDR(m->packet_type) == 0 &&
        eth_hdr->ether_type != htons(RTE_ETHER_TYPE_IPV4)) {
        return;
    }

    struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

    /* Only perform NAT on TCP and UDP. */
    if (ipv4_hdr->next_proto_id != IPPROTO_TCP && ipv4_hdr->next_proto_id != IPPROTO_UDP) {
        return;
    }

    /* Required to edit the TCP/UDP ports in memory. */
    uint16_t src_port, dst_port;
    struct rte_tcp_hdr *tcp = NULL;
    struct rte_udp_hdr *udp = NULL;

    int ip_hdr_len = (ipv4_hdr->version_ihl & 0x0f) * 4;

    if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
        tcp = (struct rte_tcp_hdr *)((unsigned char *)ipv4_hdr + ip_hdr_len);
        src_port = tcp->src_port;
        dst_port = tcp->dst_port;
    } else {
        udp = (struct rte_udp_hdr *)((unsigned char *)ipv4_hdr + ip_hdr_len);
        src_port = udp->src_port;
        dst_port = udp->dst_port;
    }

    struct nat_outbound_key out_key;
    /* Remove any garbage or the hash will be unpredictable. */
    memset(&out_key, 0, sizeof(out_key));
    out_key.src_ip = ipv4_hdr->src_addr;
    out_key.dst_ip = ipv4_hdr->dst_addr;
    out_key.src_port = src_port;
    out_key.dst_port = dst_port;
    out_key.proto = ipv4_hdr->next_proto_id;

    void *wan_port_ptr;

    /* Check if we have an active connection already, if yes: fill in wan_port_ptr. */
    int ret = rte_hash_lookup_data(outbound_hash, &out_key, &wan_port_ptr);
    uint16_t wan_port;

    if (ret < 0) {
        /* Need to allocate a new port for the new connection. */
        void *free_port;

        if (rte_ring_dequeue(port_pool, &free_port) < 0) {
            rte_pktmbuf_free(m);
            return;
        }

        rte_hash_add_key_data(outbound_hash, &out_key, free_port);

        wan_port = (uint16_t)(uintptr_t)free_port;

        /* Prepare the key for the Inbound reply traffic. */
        struct nat_inbound_key in_key;
        memset(&in_key, 0, sizeof(in_key));
        in_key.wan_port = wan_port;
        in_key.proto = ipv4_hdr->next_proto_id;

        /* The way the IP:PORT is using a 64-bit int with the 32-bit IP in the higher half and the
         * 16-bit port in the lower half. */
        uint64_t internal_ip_64 = (uint64_t)out_key.src_ip;
        uint64_t internal_port_64 = (uint64_t)out_key.src_port;
        uint64_t in_val = (internal_ip_64 << 32) | internal_port_64;

        rte_hash_add_key_data(inbound_hash, &in_key, (void *)(uintptr_t)in_val);
    } else {
        /* Found an active port for this connection. */
        wan_port = (uint16_t)(uintptr_t)wan_port_ptr;
    }

    /* Masquerade. */
    ipv4_hdr->src_addr = g_wan_ip;
    if (tcp) {
        tcp->src_port = wan_port;
    } else if (udp) {
        udp->src_port = wan_port;
    }

    /* Fix the checksum, must remove the old checksum to avoid corrupted result. */
    ipv4_hdr->hdr_checksum = 0;
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

    if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((unsigned char *)ipv4_hdr + ip_hdr_len);
        tcp->cksum = 0;
        tcp->cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, tcp);
    } else {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)((unsigned char *)ipv4_hdr + ip_hdr_len);
        udp->dgram_cksum = 0;
        udp->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, udp);
    }
}

int nat_inbound(struct rte_mbuf *m) {
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    if (eth_hdr->ether_type != htons(RTE_ETHER_TYPE_IPV4)) {
        return 0;
    }

    struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

    if (ipv4_hdr->dst_addr != g_wan_ip) {
        return 0;
    }

    if (ipv4_hdr->next_proto_id != IPPROTO_TCP && ipv4_hdr->next_proto_id != IPPROTO_UDP) {
        return 0;
    }

    uint16_t dst_port;
    struct rte_tcp_hdr *tcp = NULL;
    struct rte_udp_hdr *udp = NULL;
    int ip_hdr_len = (ipv4_hdr->version_ihl & 0x0f) * 4;

    if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
        tcp = (struct rte_tcp_hdr *)((unsigned char *)ipv4_hdr + ip_hdr_len);
        dst_port = tcp->dst_port;
    } else {
        udp = (struct rte_udp_hdr *)((unsigned char *)ipv4_hdr + ip_hdr_len);
        dst_port = udp->dst_port;
    }

    struct nat_inbound_key in_key;
    memset(&in_key, 0, sizeof(in_key));
    in_key.wan_port = dst_port;
    in_key.proto = ipv4_hdr->next_proto_id;

    void *in_val_ptr;
    int ret = rte_hash_lookup_data(inbound_hash, &in_key, &in_val_ptr);
    if (ret < 0) {
        /* No active NAT session. */
        return 0;
    }

    /* Unpack the original internal IP and port from the pointer. */
    uint64_t in_val = (uint64_t)(uintptr_t)in_val_ptr;
    uint32_t internal_ip = (uint32_t)(in_val >> 32);
    uint16_t internal_port = (uint16_t)(in_val & 0xFFFFF);

    /* De-masquerade. */
    ipv4_hdr->dst_addr = internal_ip;

    if (tcp) {
        tcp->dst_port = internal_port;
    } else if (udp) {
        udp->dst_port = internal_port;
    }

    ipv4_hdr->hdr_checksum = 0;
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

    if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
        tcp->cksum = 0;
        tcp->cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, tcp);
    } else {
        udp->dgram_cksum = 0;
        udp->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, udp);
    }

    return 1; // Successfully translated.
}