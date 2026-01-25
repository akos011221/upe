#define _POSIX_C_SOURCE 200809L
#ifndef NDP_TABLE_H
#define NDP_TABLE_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

typedef struct {
    uint8_t ip[16];
    uint8_t mac[6];
    time_t update_at;
    bool valid;
} ndp_entry_t;

typedef struct {
    ndp_entry_t *entries;
    size_t capacity;
    pthread_rwlock_t lock;
} ndp_table_t;

int ndp_table_init(ndp_table_t *t, size_t capacity);
void ndp_table_destroy(ndp_table_t *t);

/* Learn / update entry in the table. */
void ndp_update(ndp_table_t *t, const uint8_t *ip, const uint8_t *mac);

/*
    Look up MAC address.
        Return true if found, false otherwise.
*/
bool ndp_get_mac(ndp_table_t *t, const uint8_t *ip, uint8_t *out_mac);

#endif