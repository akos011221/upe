#include "lpm.h"
#include <arpa/inet.h>
#include <string.h>

static inline uint32_t compute_mask(uint8_t prefix_len) {
    /* Prevent shift by 32 (undefined behavior) */
    if (prefix_len == 0) {
        return 0;
    }
    // ~0u is all 1s
    return htonl(~0u << (32 - prefix_len));
}

void lpm_init(lpm_table_t *table) {
    if (!table) return;
    memset(table, 0, sizeof(lpm_table_t));
}

bool lpm_insert(lpm_table_t *table, uint32_t prefix, uint8_t prefix_len, uint32_t next_hop_ip,
                uint16_t egress_port) {
    if (!table || prefix_len > 32) return false;

    uint32_t mask = compute_mask(prefix_len);
    uint32_t masked_prefix = prefix & mask;

    /* Overwrite if there's a duplicate */
    for (uint32_t i = 0; i < table->count; i++) {
        if (table->entries[i].valid && table->entries[i].prefix == masked_prefix &&
            table->entries[i].prefix_len == prefix_len) {
            table->entries[i].next_hop_ip = next_hop_ip;
            table->entries[i].egress_port = egress_port;
            return true;
        }
    }

    if (table->count >= LPM_TABLE_CAPACITY) {
        return false;
    }

    /* Otherwise append new route */
    uint32_t idx = table->count++;
    table->entries[idx].prefix = masked_prefix;
    table->entries[idx].prefix_len = prefix_len;
    table->entries[idx].next_hop_ip = next_hop_ip;
    table->entries[idx].egress_port = egress_port;
    table->entries[idx].valid = true;

    return true;
}

bool lpm_lookup(const lpm_table_t *table, uint32_t dest_ip, uint32_t *out_next_hop,
                uint16_t *out_port) {
    if (!table || !out_next_hop || !out_port) return false;

    int best_match_idx = -1;
    int max_prefix_len = -1;

    /* Linear scan to get the longest active subnetwork match */
    for (uint32_t i = 0; i < table->count; i++) {
        if (!table->entries[i].valid) continue;

        uint32_t mask = compute_mask(table->entries[i].prefix_len);

        /* Does the destination IP fall inside the subnet block? */
        if ((dest_ip & mask) == table->entries[i].prefix) {
            if ((int)table->entries[i].prefix_len > max_prefix_len) {
                max_prefix_len = table->entries[i].prefix_len;
                best_match_idx = (int)i;
            }
        }
    }

    if (best_match_idx != -1) {
        *out_next_hop = table->entries[best_match_idx].next_hop_ip;
        *out_port = table->entries[best_match_idx].egress_port;
        return true;
    }

    return false; /* No Route Found */
}