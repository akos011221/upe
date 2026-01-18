#include "parser.h"
#include "log.h"
#include <arpa/inet.h>
#include <string.h>

/*
    `packed` is used for each network struct.
    CPU's rule is to read a 4-byte integer (uint32_t), the memory address MUST
    be divisibly by 4.

    If you try to read a `uint_32_t` from 0x1001, the CPU hardware cannot do it
    in a single cycle and raises hardware exception (Signal: `SUGBUS` or `SIGSEGV`).

    The solution is `__attribute__((packed))`, which tells the compiler that the
    struct might sit at any byte address. Don't assume it is aligned.
*/

struct eth_hdr {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
} __attribute__((packed));

struct ipv4_hdr {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} __attribute__((packed));

struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed));

struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
} __attribute__((packed));

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} __attribute__((packed));

int parse_flow_key(const uint8_t *pkt, size_t len, flow_key_t *out) {
    /* Ethernet header */
    if (len < sizeof(struct eth_hdr)) {
        return -1;
    }

    const struct eth_hdr *eth = (const struct eth_hdr *)pkt;

    uint16_t ethertype = ntohs(eth->ethertype);

    if (ethertype != 0x0800) {
        return -1;
    }

    /* IPv4 header */
    const uint8_t *ip_ptr = pkt + sizeof(struct eth_hdr);
    size_t ip_len = len - sizeof(struct eth_hdr);

    if (ip_len < sizeof(struct ipv4_hdr)) {
        return -1;
    }

    const struct ipv4_hdr *ip = (const struct ipv4_hdr *)ip_ptr;

    uint8_t version = ip->ver_ihl >> 4;
    uint8_t ihl = ip->ver_ihl & 0x0F;

    size_t ip_hdr_len = ihl * 4;

    if (version != 4 || ip_hdr_len < sizeof(struct ipv4_hdr) || ip_len < ip_hdr_len) {
        return -1;
    }

    out->src_ip = ntohl(ip->src_ip);
    out->dst_ip = ntohl(ip->dst_ip);
    out->protocol = ip->protocol;

    /* Transport header */
    const uint8_t *l4_ptr = ip_ptr + ip_hdr_len;
    size_t l4_len = ip_len - ip_hdr_len;

    if (out->protocol == 17) {
        if (l4_len < sizeof(struct udp_hdr)) {
            return -1;
        }

        const struct udp_hdr *udp = (const struct udp_hdr *)l4_ptr;

        out->src_port = ntohs(udp->src_port);
        out->dst_port = ntohs(udp->dst_port);
    } else if (out->protocol == 6) {
        if (l4_len < sizeof(struct tcp_hdr)) {
            return -1;
        }

        const struct tcp_hdr *tcp = (const struct tcp_hdr *)l4_ptr;

        uint8_t data_offset_words = tcp->data_offset >> 4;
        size_t tcp_hdr_len = data_offset_words * 4;

        if (tcp_hdr_len < sizeof(struct tcp_hdr) || l4_len < tcp_hdr_len) {
            return -1;
        }

        out->src_port = ntohs(tcp->src_port);
        out->dst_port = ntohs(tcp->dst_port);
    } else if (out->protocol == 1) {
        if (l4_len < sizeof(struct icmp_hdr)) {
            return -1;
        }

        const struct icmp_hdr *icmp = (const struct icmp_hdr *)l4_ptr;
        // Map ICMP Identifier to SPORT, and Type/Code to DPORT
        out->src_port = ntohs(icmp->id);
        // Pack two 8-bit values into one 16-bit integer:
        // move `type` onto the high byte, `code` to the low byte.
        out->dst_port = (uint16_t)((icmp->type << 8) | icmp->code);
    } else {
        return -1;
    }

    return 0;
}

uint32_t flow_hash(const flow_key_t *k) {
    if (!k) return 0;
    return k->src_ip ^ k->dst_ip ^ k->src_port ^ k->dst_port ^ k->protocol;
}