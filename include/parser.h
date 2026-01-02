#ifndef PARSER_H
#define PARSER_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t protocol;
} ipv4_info_t;

/*
    Attempts to parse Ethernet and IPv4 headers from the packet.
    Returns 0 if successful, -1 if not.
*/
int parse_ipv4(const uint8_t *pkt, size_t len, ipv4_info_t *out);

#endif