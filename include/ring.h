#ifndef RING_H
#define RING_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    void **slots;    // void, so ring doesn't have to know about pktbuf_t*
    size_t capacity; // must be power of two
    size_t mask;

    // producer writes at head
    // consumer reads at tail
    atomic_size_t head;
    atomic_size_t tail;
} spsc_ring_t;

int ring_init(spsc_ring_t *r, size_t capacity);
void ring_destroy(spsc_ring_t *r);

/*
    Producer: Push a pointer into ring.
        Returns false if ring is full.
*/
bool ring_push(spsc_ring_t *r, void *ptr);

/*
    Consumer: Pop a pointer from ring.
        Returns NULL if ring is empty.
*/
void *ring_pop(spsc_ring_t *r);

#endif