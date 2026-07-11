#ifndef LPM_H
#define LPM_H

#include <stdint.h>
#include <stdbool.h>

#define LPM_TABLE_CAPACITY 1024

typedef struct {
    uint32_t    prefix;         /* Network byte order */
    uint8_t     prefix_len;
    uint32_t    next_hop_ip;    /* Network byte order */
    uint16_t    egress_port;
    bool        valid;
} lpm_entry_t;

typedef struct {
    lpm_entry_t entries[LPM_TABLE_CAPACITY];
    uint32_t    count;
} lpm_table_t;

/* API Methods */
void lpm_init(lpm_table_t *table);
bool lpm_insert(lpm_table_t *table, uint32_t prefix, uint8_t prefix_len, uint32_t next_hop_ip, uint16_t egress_port);
bool lpm_lookup(const lpm_table_t *table, uint32_t dest_ip, uint32_t *out_next_hop, uint16_t *out_port);

#endif /* LPM_H */
