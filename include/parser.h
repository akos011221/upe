#ifndef PARSER_H
#define PARSER_H

#include <stddef.h>
#include <stdint.h>

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

#endif