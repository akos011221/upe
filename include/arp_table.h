#define _POSIX_C_SOURCE 200809L
#ifndef ARP_TABLE_H
#define ARP_TABLE_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

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

#endif