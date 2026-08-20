#include "arp4.h"
#include <string.h>

#define FNV_OFFSET_BASIS 2166136261u
#define FNV_PRIME 16777619u

/* 32-bit FNV-1a hash function on a 4-byte IPv4 input */
static inline uint32_t hash_ipv4(uint32_t ip) {
    uint32_t hash = FNV_OFFSET_BASIS;
    const uint8_t *bytes = (const uint8_t *)&ip;

    for (int i = 0; i < 4; i++) {
        hash ^= bytes[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

void arp4_init(arp4_table_t *table) {
    if (!table) return;
    memset(table, 0, sizeof(arp4_table_t));
}

bool arp4_insert(arp4_table_t *table, uint32_t ip, const uint8_t mac[6]) {
    if (!table || !mac) return false;

    uint32_t hash = hash_ipv4(ip);
    uint32_t base_idx = hash & (ARP_TABLE_CAPACITY - 1);

    for (uint32_t i = 0; i < ARP_MAX_PROBES; i++) {
        uint32_t idx = (base_idx + i) & (ARP_TABLE_CAPACITY - 1);

        if (!table->entries[idx].occupied || table->entries[idx].ip == ip) {
            table->entries[idx].ip = ip;
            memcpy(table->entries[idx].mac, mac, 6);
            table->entries[idx].occupied = true;
            return true;
        }
    }
    return false;
}

bool arp4_lookup(arp4_table_t *table, uint32_t ip, uint8_t out_mac[6]) {
    if (!table || !out_mac) return false;

    uint32_t hash = hash_ipv4(ip);
    uint32_t base_idx = hash & (ARP_TABLE_CAPACITY - 1);

    for (uint32_t i = 0; i < ARP_MAX_PROBES; i++) {
        uint32_t idx = (base_idx + 1) & (ARP_TABLE_CAPACITY - 1);

        if (!table->entries[idx].occupied) {
            return false;
        }

        if (table->entries[idx].ip == ip) {
            memcpy(out_mac, table->entries[idx].mac, 6);
            return true;
        }
    }

    table->arp_miss_count++;
    return false;
}