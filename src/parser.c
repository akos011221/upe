#include "parser.h"
#include "log.h"
#include <arpa/inet.h>
#include <string.h>

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