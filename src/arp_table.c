#include "arp_table.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int arp_table_init(arp_table_t *t, size_t capacity) {
    if (!t || capacity == 0 || (capacity & (capacity - 1)) != 0) return -1;

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

    size_t idx = ip & (t->capacity - 1);

    pthread_rwlock_wrlock(&t->lock);

    for (size_t i = 0; i < t->capacity; i++) {
        size_t curr = (idx + i) & (t->capacity - 1);

        if (!t->entries[curr].valid) {
            /* Empty slot, insert here. */
            t->entries[curr].valid = true;
            t->entries[curr].ip = ip;
            memcpy(t->entries[curr].mac, mac, 6);
            t->entries[curr].update_at = time(NULL);
            break;
        }

        if (t->entries[curr].ip == ip) {
            /* Existing entry, update it. */
            memcpy(t->entries[curr].mac, mac, 6);
            t->entries[curr].update_at = time(NULL);
            break;
        }
    }
    pthread_rwlock_unlock(&t->lock);
}

bool arp_get_mac(arp_table_t *t, uint32_t ip, uint8_t *out_mac) {
    if (!t || !out_mac) return false;

    size_t idx = ip & (t->capacity - 1);

    pthread_rwlock_rdlock(&t->lock);
    for (size_t i = 0; i < t->capacity; i++) {
        size_t curr = (idx + i) & (t->capacity - 1);

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

size_t arp_expire(arp_table_t *t, time_t now) {
    if (!t) return 0;

    size_t evicted = 0;

    pthread_rwlock_wrlock(&t->lock);

    for (size_t i = 0; i < t->capacity; i++) {
        if (!t->entries[i].valid) continue;

        if (now - t->entries[i].update_at < (time_t)ARP_TIMEOUT_SEC) continue;

        /* Mark the slot empty, then rehash the cluster that follows it.
         *
         * Why: open-addressing lookup stops at the first empty slot. If we
         * blank a slot in the middle of the chain, entries probed past it become
         * unreachable. We fix this by shifting each subsequent entry in the same
         * cluster back into its natural position.
        */
        t->entries[i].valid = false;
        evicted++;

        size_t hole = i;
        size_t j    = (i + 1) & (t->capacity - 1);

        while(t->entries[j].valid) {
            /* Where is this entry ideally? */
            size_t ideal = t->entries[j].ip & (t->capacity - 1);

            /* If `ideal` falls in (hole..j], moving it to `hole`
             * keeps it at or before its ideal slot.
            */
            bool should_move;
            if (hole <= j) {
                should_move = (ideal <= hole) || (ideal > j);
            } else {
                /* Probe chain wrapped around the end of the array. */
                should_move = (ideal <= hole) && (ideal > j);
            }

            if (should_move) {
                t->entries[hole] = t->entries[j];
                t->entries[j].valid = false;
                hole = j;
            }

            j = (j + 1) & (t->capacity - 1);

            /* An empty slot marks the end of this cluster. */
            if (!t->entries[j].valid) break;
        }
    }

    pthread_rwlock_unlock(&t->lock);
    return evicted;
}