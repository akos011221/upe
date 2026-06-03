#define _POSIX_C_SOURCE 200809L
#ifndef ARP_TABLE_H
#define ARP_TABLE_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* Entries must be refreshed within this window or will be removed. */
#define ARP_TIMEOUT_SEC 300

typedef struct {
    uint32_t ip;
    uint8_t mac[6];
    time_t update_at;
    bool valid;
} arp_entry_t;

typedef struct {
    arp_entry_t *entries;
    size_t capacity;
    pthread_rwlock_t lock;
} arp_table_t;

int arp_table_init(arp_table_t *t, size_t capacity);
void arp_table_destroy(arp_table_t *t);

/* Learn or update an entry. */
void arp_update(arp_table_t *t, uint32_t ip, const uint8_t *mac);

/*
    Look up MAC address.
        Return true if found, false otherwise.
*/
bool arp_get_mac(arp_table_t *t, uint32_t ip, uint8_t *out_mac);

/*
    Remove all entries that have update_at older than ARP_TIMEOUT_SEC seconds
    relative to `now`.
        Returns the number of entries that were evicted.
*/
size_t arp_expire(arp_table_t *t, time_t now);

#endif