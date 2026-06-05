#include "mac_table.h"
#include <string.h>
#include <stdio.h>

static uint32_t mac_hash(const uint8_t mac[MAC_ADDR_LEN]) {
    /* FNV-1a hash */
    uint32_t hash = 2166136261u;
    for (int i = 0; i < MAC_ADDR_LEN; i++) {
        hash ^= mac[i];
        hash *= 16777619u;
    }
    return hash;
}

/* Compare two MAC addresses */
static bool mac_equal(const uint8_t mac1[MAC_ADDR_LEN],
                      const uint8_t mac2[MAC_ADDR_LEN]) {
    return memcmp(mac1, mac2, MAC_ADDR_LEN) == 0;
}

void mac_table_init(mac_table_t *table, uint32_t aging_timeout_sec,
                    double cycles_per_ns) {
    memset(table, 0, sizeof(*table));
    /* Convert seconds to TSC cycles */
    table->aging_timeout_tsc = (uint64_t)(aging_timeout_sec *
                                1000000000.0 * cycles_per_ns);
}

bool mac_table_insert(mac_table_t *table, const uint8_t mac[MAC_ADDR_LEN],
                      uint16_t port_id, uint64_t current_tsc) {
    uint32_t hash = mac_hash(mac);
    uint32_t index = hash & (MAC_TABLE_CAPACITY - 1);

    for (uint32_t probe = 0; probe < MAC_TABLE_MAX_PROBE; probe++) {
        uint32_t slot = (index + probe) & (MAC_TABLE_CAPACITY - 1);
        mac_entry_t *entry = &table->entries[slot];

        /* Two birds, one stone: with this we also clean up expired slots */
        bool expired = entry->occupied &&
                       (current_tsc - entry->last_seen_tsc) > table->aging_timeout_tsc;
        
        /* Empty slot or expired entry or matching MAC */
        if (!entry->occupied || expired || mac_equal(entry->mac, mac)) {
            memcpy(entry->mac, mac, MAC_ADDR_LEN);
            entry->port_id = port_id;
            entry->last_seen_tsc = current_tsc;
            entry->occupied = true;
            return true;
        }
    }

    /* Table full, no slot within probe distance */
    table->table_full_count++;
    return false;
}

bool mac_table_lookup(mac_table_t *table, const uint8_t mac[MAC_ADDR_LEN],
                      uint64_t current_tsc, uint16_t *out_port) {
    uint32_t hash = mac_hash(mac);
    uint32_t index = hash & (MAC_TABLE_CAPACITY - 1);

    for (uint32_t probe = 0; probe < MAC_TABLE_MAX_PROBE; probe++) {
        uint32_t slot = (index + probe) & (MAC_TABLE_CAPACITY - 1);
        mac_entry_t *entry = &table->entries[slot];

        if (!entry->occupied) {
            /* Empty slot: MAC is not in table */
            return false;
        }

        if (mac_equal(entry->mac, mac)) {
            /* Found matching MAC, but is it expired? */
            if ((current_tsc - entry->last_seen_tsc) > table->aging_timeout_tsc) {
                entry->occupied = false;
                return false;
            }
            *out_port = entry->port_id;
            return true;
        }
    }

    return false;
}
