#include "arp_table.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARP_TIMEOUT_SEC 300

int arp_table_init(arp_table_t *t, size_t capacity) {
    if (!t || capacity == 0) return -1;

    t->entries = (arp_entry_t *)calloc(capacity, sizeof(arp_entry_t));
    if (!t->entries) return -1;

    t->capacity = capacity;
    pthread_rwlock_init(&t->lock, NULL);
    return 0;
}

void arp_table_destroy(arp_table_t *t) {
    if (!t) return;
    pthread_rwlock_destroy(&t->lock);
    free(t->entries);
    t->entries = NULL;
    t->capacity = 0;
}

void arp_update(arp_table_t *t, uint32_t ip, const uint8_t *mac) {
    if (!t || !mac) return;

    size_t idx = ip % t->capacity;

    pthread_rwlock_wrlock(&t->lock);

    for (size_t i = 0; i < t->capacity; i++) {
        size_t curr = (idx + i) % t->capacity;

        if (!t->entries[curr].valid) {
            // Empty slot, insert here.
            t->entries[curr].valid = true;
            t->entries[curr].ip = ip;
            memcpy(t->entries[curr].mac, mac, 6);
            t->entries[curr].update_at = time(NULL);
            break;
        }

        if (t->entries[curr].ip == ip) {
            // Existing entry, update it.
            memcpy(t->entries[curr].mac, mac, 6);
            t->entries[curr].update_at = time(NULL);
            break;
        }
    }
    pthread_rwlock_unlock(&t->lock);
}

bool arp_get_mac(arp_table_t *t, uint32_t ip, uint8_t *out_mac) {
    if (!t || !out_mac) return false;

    size_t idx = ip % t->capacity;

    pthread_rwlock_rdlock(&t->lock);
    for (size_t i = 0; i < t->capacity; i++) {
        size_t curr = (idx + i) % t->capacity;

        if (t->entries[curr].valid && t->entries[curr].ip == ip) {
            memcpy(out_mac, t->entries[curr].mac, 6);
            pthread_rwlock_unlock(&t->lock);
            return true;
        }

        /*
            This would have been a valid spot for the entry, but it is not here.
            Then, it will not be further in the hash map either, because the current
            implementation of ARP table does not support deletion -> no tombstones.
        */
        if (!t->entries[curr].valid) break;
    }
    pthread_rwlock_unlock(&t->lock);

    return false;
}