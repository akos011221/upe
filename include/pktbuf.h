#ifndef PKTBUF_H
#define PKTBUF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PKTBUF_DATA_SIZE 2048 // MTU

typedef struct pktbuf {
    uint64_t timestamp; /* TSC cycle count at RX arrival */
    size_t len;
    uint8_t data[PKTBUF_DATA_SIZE];
} pktbuf_t;

typedef struct {
    pktbuf_t *buffers;       // Contiguous array of all buffers.
    pktbuf_t **free_stack;   // Stack of pointers to free buffers.
    _Atomic size_t top;      // Stack top index, modified using atomic CAS.
    size_t capacity;         // Total number of buffers in the pool.
    size_t buffers_mmap_len; // Size of mmap (rounded to 2MB). 0 if calloc was used.
    bool use_hugepages;      // Whether to use hugepages (informational).
} pktbuf_pool_t;

int pktbuf_pool_init(pktbuf_pool_t *p, size_t capacity);
void pktbuf_pool_destroy(pktbuf_pool_t *p);

/*
    Get a buffer from the pool.

    Fast path: Returns buffers from thread-local cache (no atomics).
    Slow path: Refills local cache from global pool (atomic CAS).

        Returns NULL if no buffers are available.
*/
pktbuf_t *pktbuf_alloc(pktbuf_pool_t *p);

/*
    Return buffer to the pool.

    Fast path: Adds to thread-local cache (no atomics).
    Slow path: Flushes excess to global poll (atomic CAS).
*/
void pktbuf_free(pktbuf_pool_t *p, pktbuf_t *buf);

#endif