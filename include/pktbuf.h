#ifndef PKTBUF_H
#define PKTBUF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PKTBUF_DATA_SIZE 2048 // MTU

typedef struct pktbuf {
    size_t len;
    uint8_t data[PKTBUF_DATA_SIZE];
    struct pktbuf *next;
} pktbuf_t;

typedef struct {
    pktbuf_t *free_list;
    size_t capacity;
    size_t available;
} pktbuf_pool_t;

int pktbuf_pool_init(pktbuf_pool_t *p, size_t capacity);
void pktbuf_pool_destroy(pktbuf_pool_t *p);

/*
    Get a buffer from the pool.
    Returns NULL if no buffers are available.
*/
pktbuf_t *pktbuf_alloc(pktbuf_pool_t *p);

/* Return buffer to the pool. */
void pktbuf_free(pktbuf_pool_t *p, pktbuf_t *buf);

#endif