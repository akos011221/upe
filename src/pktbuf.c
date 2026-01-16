#include "pktbuf.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static pthread_mutex_t g_pool_lock = PTHREAD_MUTEX_INITIALIZER;
#define CACHE_SIZE 32
#define BURST_SIZE 16 // How many to move to/from the global pool at once

typedef struct {
    pktbuf_pool_t *pool;         // Cache's pool
    int count;                   // Number of items in the cache
    pktbuf_t *items[CACHE_SIZE]; // The cache itself
} thread_cache_t;

// __thread makes every thread get its own instance of the struct.
static __thread thread_cache_t t_cache;

int pktbuf_pool_init(pktbuf_pool_t *p, size_t capacity) {
    if (!p || capacity == 0) return -1;

    p->free_list = NULL;
    p->capacity = capacity;
    p->available = 0;

    for (size_t i = 0; i < capacity; i++) {
        pktbuf_t *b = (pktbuf_t *)calloc(1, sizeof(pktbuf_t));
        if (!b) return -1;

        // Insert into free list
        b->next = p->free_list;
        p->free_list = b;
        p->available++;
    }

    return 0;
}

void pktbuf_pool_destroy(pktbuf_pool_t *p) {
    if (!p) return;

    pthread_mutex_lock(&g_pool_lock);
    pktbuf_t *cur = p->free_list;
    while (cur) {
        pktbuf_t *n = cur->next;
        free(cur);
        cur = n;
    }
    p->free_list = NULL;
    p->available = 0;
    p->capacity = 0;
    pthread_mutex_unlock(&g_pool_lock);
}

pktbuf_t *pktbuf_alloc(pktbuf_pool_t *p) {
    if (!p) return NULL;

    if (t_cache.pool != p) {
        t_cache.pool = p;
        t_cache.count = 0;
    }

    // Fast path: allocate from local cache
    if (t_cache.count > 0) {
        return t_cache.items[--t_cache.count];
    }

    // Slow path: cache is empty, refill from global pool
    pthread_mutex_lock(&g_pool_lock);
    int moved = 0;
    while (moved < BURST_SIZE && p->free_list != NULL) {
        pktbuf_t *b = p->free_list;
        p->free_list = b->next;
        b->next = NULL;

        t_cache.items[moved++] = b;
        p->available--;
    }
    pthread_mutex_unlock(&g_pool_lock);

    t_cache.count = moved;

    // Retry fast path
    if (t_cache.count > 0) {
        return t_cache.items[--t_cache.count];
    }

    return NULL; // Pool is empty.
}

void pktbuf_free(pktbuf_pool_t *p, pktbuf_t *b) {
    if (!p || !b) return;

    // Note: allocated buffer is private to the thread.
    b->len = 0;

    if (t_cache.pool != p) {
        t_cache.pool = p;
        t_cache.count = 0;
    }

    // Fast path: free to the local cache
    if (t_cache.count < CACHE_SIZE) {
        t_cache.items[t_cache.count++] = b;
        return;
    }

    // Slow path: cache is full, flush BURST_SIZE to global pool
    pthread_mutex_lock(&g_pool_lock);
    for (int i = 0; i < BURST_SIZE; i++) {
        // Take from cache and push to global list
        pktbuf_t *item = t_cache.items[--t_cache.count];

        item->next = p->free_list;
        p->free_list = item;
        p->available++;
    }
    pthread_mutex_unlock(&g_pool_lock);

    // Now there's space in the cache
    t_cache.items[t_cache.count++] = b;
}