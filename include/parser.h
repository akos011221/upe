#ifndef PARSER_H
#define PARSER_H

#include <stddef.h>
#include <stdint.h>

/* Network Headers */
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

/* ------------------------------------------ */

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} flow_key_t;

/*
    Parses a packet and builds a flow key.
    Returns 0 if successful, -1 if not.
*/
int parse_flow_key(const uint8_t *pkt, size_t len, flow_key_t *out);

// Calculate symmetric 5-tuple hash for Software RSS.
uint32_t flow_hash(const flow_key_t *k);

#endif