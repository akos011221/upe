#ifndef ARP4_H
#define ARP4_H

#include <cstdint>
#include <stdint.h>
#include <stdbool.h>

#define ARP_TABLE_CAPACITY  512
#define ARP_MAX_PROBES      16

typedef struct {
    uint32_t    ip;     /* Network byte order key */
    uint8_t     mac[6]; /* Resolved value */
    bool        occupied;
} arp4_entry_t;

typedef struct {
    arp4_entry_t entries[ARP_TABLE_CAPACITY];
    uint32_t     arp_miss_count;
} arp4_table_t;

/* API Methods */
void arp4_init(arp4_table_t *table);
bool arp4_insert(arp4_table_t *table, uint32_t ip, const uint8_t mac[6]);
bool arp4_lookup(arp4_table_t *table, uint32_t ip, uint8_t out_mac[6]);

#endif /* ARP4_H */