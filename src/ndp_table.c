#include "ndp_table.h"

#include <stdlib.h>
#include <string.h>

static size_t hash_ipv6(const uint8_t *ip, size_t capacity) {
    /* Fold the 16 bytes, XOR the parts */
    uint32_t h = 0;
    const uint32_t *p = (const uint32_t *)ip;

    for (int i = 0; i < 4; i++) {
        h ^= p[i];
    }
    return h % capacity;
}

int ndp_table_init(ndp_table_t *t, size_t capacity) {
    if (!t || capacity == 0) return -1;

    t->entries = (ndp_entry_t *)calloc(capacity, sizeof(ndp_entry_t));
    if (!t->entries) return -1;

    t->capacity = capacity;
    pthread_rwlock_init(&t->lock, NULL);
    return 0;
}

void ndp_table_destroy(ndp_table_t *t) {
    if (!t) return;

    pthread_rwlock_destroy(&t->lock);
    free(t->entries);
    t->entries = NULL;
    t->capacity = 0;
}

void ndp_update(ndp_table_t *t, const uint8_t *ip, const uint8_t *mac) {
    if (!t || !ip || !mac) return;

    size_t idx = hash_ipv6(ip, t->capacity);

    pthread_rwlock_wrlock(&t->lock);
    for (size_t i = 0; i < t->capacity; i++) {
        size_t curr = (idx + i) % t->capacity;

        if (!t->entries[curr].valid) {
            /* Empty slot */
            t->entries[curr].valid = true;
            memcpy(t->entries[curr].ip, ip, 16);
            memcpy(t->entries[curr].mac, mac, 6);
            t->entries[curr].update_at = time(NULL);
            break;
        }

        if (memcmp(t->entries[curr].ip, ip, 16) == 0) {
            /* Update existing entry */
            memcpy(t->entries[curr].mac, mac, 6);
            t->entries[curr].update_at = time(NULL);
            break;
        }
    }
    pthread_rwlock_unlock(&t->lock);
}

bool ndp_get_mac(ndp_table_t *t, const uint8_t *ip, uint8_t *out_mac) {
    if (!t || !ip || !out_mac) return false;

    size_t idx = hash_ipv6(ip, t->capacity);

    pthread_rwlock_rdlock(&t->lock);
    for (size_t i = 0; i < t->capacity; i++) {
        size_t curr = (idx + i) % t->capacity;

        if (t->entries[curr].valid && memcmp(t->entries[curr].ip, ip, 16) == 0) {
            memcpy(out_mac, t->entries[curr].mac, 6);
            pthread_rwlock_unlock(&t->lock);
            return true;
        }

        if (!t->entries[curr].valid) break;
    }
    pthread_rwlock_unlock(&t->lock);
    return false;
}