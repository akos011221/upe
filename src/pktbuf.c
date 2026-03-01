#include "pktbuf.h"
#include "log.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define LOCAL_CACHE_SIZE 64
#define BULK_TRANSFER_SIZE (LOCAL_CACHE_SIZE / 2)
#define HUGE_PAGE_SIZE (2UL * 1024 * 1024) // 2 MB
#define MMAP_HUGE_2MB_FLAG (21 << MAP_HUGE_SHIFT)
#define ALIGN_UP(n, align) (((n) + (align) - 1) & ~((align) - 1))

typedef struct {
    pktbuf_pool_t *pool;
    size_t count;
    pktbuf_t *items[LOCAL_CACHE_SIZE];
} local_cache_t;

/*
    Thread-local cache instance.
    _Alignas(64) is to make sure cache starts on a cache line boundary.
    This should prevent false sharing if other thread-local variables are nearby.
    (Initialized to zero: pool=NULL, count=0, items all NULL.)
*/
static _Thread_local _Alignas(64) local_cache_t t_cache = {0};

/*
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
Global Pool Operations
- A stack implemented as an array with an atomic top index
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
*/

/*
    Pop multiple buffers from the global pool (lock-free).

    Parameters:
        - pool:     Buffer pool
        - out:      Array to store popped buffer pointers
        - request:  Maximum number of buffers to pop

        Return: Actual number of buffers popped.

    Steps:
        1) Read current top.
        2) Calculate how many can be popped.
        3) Try to update top atomically using CAS.
        4) If CAS fails (another thread modified top), retry from step 1.
        5) If CAS succeeds, copy the buffer pointers.
*/
static size_t global_pop_bulk(pktbuf_pool_t *pool, pktbuf_t **out, size_t request) {
    size_t old_top;
    size_t new_top;
    size_t actual;

    /* CAS retry loop */
    do {
        // ACQUIRE load so we see buffer pointers published by prior RELEASE stores.
        old_top = atomic_load_explicit(&pool->top, memory_order_acquire);

        // Calculate how many buffers we can take.
        if (old_top == 0) {
            return 0; // Pool is empty.
        }

        actual = (old_top < request) ? old_top : request;
        new_top = old_top - actual;

        /*
        CAS loop to update the global top.

        Weak CAS is used for performance, as even if CAS fails for no reason, the loop retries.

        Memory ordering:
        -   Success (ACQ_REL): acquire ownership of popped buffers and release the updated top to
                               other threads.
        -   Failure (ACQUIRE): look at the latest top value before retrying.
        */
    } while (!atomic_compare_exchange_weak_explicit(&pool->top,           // object
                                                    &old_top,             // expected
                                                    new_top,              // desired
                                                    memory_order_acq_rel, // success order
                                                    memory_order_acquire  // failure order
                                                    ));

    /*
    CAS succeded. Copy buffer pointers to output array.

    The successful CAS reserves the range [new_top, old_top) for this thread,
    so it is safe to read and copy those entries into the output array.

    Example: old_top=10, actual=3 -> indices [7,10) → 7, 8, 9
    */
    for (size_t i = 0; i < actual; i++) {
        out[i] = pool->free_stack[new_top + i];
    }

    return actual;
}

/*
    Push multiple buffers to the global pool (lock-free).

    Parameters:
        - pool:     Buffer pool
        - bufs:     Array of buffer pointers to push
        - count:    Number of buffers to push
*/
static void global_push_bulk(pktbuf_pool_t *pool, pktbuf_t **bufs, size_t count) {
    size_t old_top;
    size_t new_top;

    /*
    Reserve space in the global stack.

    Speculatively write buffers above the current top, then publish
    them by advancing `top` via CAS.

    Slots at indices >= top are not visible to poppers. A successful CAS
    publishes the new range; failed CAS attempts discard the speculative writes.
    */
    do {
        old_top = atomic_load_explicit(&pool->top, memory_order_acquire);
        new_top = old_top + count;

        // Speculative writes of our buffers to the stack. Slots are above top, no one is reading
        // them.
        for (size_t i = 0; i < count; i++) {
            pool->free_stack[old_top + i] = bufs[i];
        }

    } while (!atomic_compare_exchange_weak_explicit(&pool->top,           // object
                                                    &old_top,             // expected
                                                    new_top,              // desired
                                                    memory_order_acq_rel, // success order
                                                    memory_order_acquire  // failure order
                                                    ));

    // CAS succeeded: our writes are now "committed" and visible to poppers.
}

/*
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
Local Cache Operations
- They include the fast-path operations; no atomics or synchronizations. (except refill and flush
from/to global pool)
- Only array indexing.
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
*/

/*
    Refill the local cache from the global pool.
    - Called when local cache is EMPTY and buffers are needed.
*/
static void refill_local_cache(pktbuf_pool_t *pool) {
    size_t got = global_pop_bulk(pool, t_cache.items, BULK_TRANSFER_SIZE);
    t_cache.count = got;
    t_cache.pool = pool;
}

/*
    Flush excess buffers from local cache to the global pool.
    - Called when local cache is FULL, to free buffers.
*/
static void flush_local_cache(pktbuf_pool_t *pool) {
    size_t return_count = BULK_TRANSFER_SIZE;
    size_t start_idx = t_cache.count - return_count; // returning from the END of the cache.

    global_push_bulk(pool, &t_cache.items[start_idx], return_count);

    t_cache.count -= return_count;
}

/*
    Flush ALL buffers from local cache to global pool.
    - Called when switching pools or during cleanup.
*/
static void flush_all_local_cache(void) {
    if (t_cache.pool != NULL && t_cache.count > 0) {
        global_push_bulk(t_cache.pool, t_cache.items, t_cache.count);
        t_cache.count = 0;
    }
}

/*
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
Public API
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
*/

int pktbuf_pool_init(pktbuf_pool_t *p, size_t capacity) {
    if (p == NULL || capacity == 0) {
        return -1;
    }

    // Allocation of the buffer array.
    size_t raw_size = capacity * sizeof(pktbuf_t);
    size_t mmap_len = ALIGN_UP(raw_size, HUGE_PAGE_SIZE);

    p->use_hugepages = false;
    p->buffers_mmap_len = 0;
    p->buffers = NULL;

    // Attempt 1: mmap with 2MB huge pages.
    void *mem = mmap(NULL, mmap_len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MMAP_HUGE_2MB_FLAG, -1, 0);

    if (mem != MAP_FAILED) {
        p->buffers = (pktbuf_t *)mem;
        p->buffers_mmap_len = mmap_len;
        p->use_hugepages = true;
        log_msg(LOG_INFO, "pktbuf: allocated %zu bytes using 2MB huge pages (%zu pages)", mmap_len,
                mmap_len / HUGE_PAGE_SIZE);
    } else {
        // Attempt 2: regular mmap (no huge pages).
        log_msg(LOG_WARN, "pktbuf: huge pages unavailable, using regular mmap");
        mem = mmap(NULL, mmap_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (mem != MAP_FAILED) {
            p->buffers = (pktbuf_t *)mem;
            p->buffers_mmap_len = mmap_len;
            log_msg(LOG_INFO, "pktbuf: allocated %zu bytes using regular mmap", mmap_len);
        } else {
            // Atempt 3: calloc as last resort.
            log_msg(LOG_WARN, "pktbuf: regular mmap failed, falling back to calloc");
            p->buffers = (pktbuf_t *)calloc(capacity, sizeof(pktbuf_t));
        }
    }

    if (p->buffers == NULL) {
        return -1;
    }

    // Allocation of the free stack (array of pointers).
    p->free_stack = (pktbuf_t **)calloc(capacity, sizeof(pktbuf_t *));
    if (p->free_stack == NULL) {
        free(p->buffers);
        p->buffers = NULL;
        return -1;
    }

    /*
    Initialize the free stack with all buffers.
    free_stack will become:
        [&buffers[0]] [&buffers[1]] ... [&buffers[capacity-1]]
    */
    for (size_t i = 0; i < capacity; i++) {
        p->free_stack[i] = &p->buffers[i];
    }

    p->capacity = capacity;

    /*
    Atomically initialize top. It will be full (top=capacity) at init.
    atomic_init: non-atomic initialization of atomic variable.
        - safe as no other thread can see 'p' yet.
    */
    atomic_init(&p->top, capacity);

    return 0;
}

void pktbuf_pool_destroy(pktbuf_pool_t *p) {
    if (p == NULL) {
        return;
    }

    /*
       Non-thread-safe operation. Threads must have stopped using the pool when calling this.
       Buffers that stuck in thread-local caches will be leaked, but the underlying memory
       (p->buffers) will be freed, causing use-after-free if any thread tries to use a cached
       buffer.
    */
    free(p->free_stack);

    if (p->buffers_mmap_len > 0) {
        munmap(p->buffers, p->buffers_mmap_len);
    } else {
        free(p->buffers);
    }

    p->free_stack = NULL;
    p->buffers = NULL;
    p->capacity = 0;
    p->buffers_mmap_len = 0;
    p->use_hugepages = false;
    atomic_store(&p->top, 0);
}

pktbuf_t *pktbuf_alloc(pktbuf_pool_t *p) {
    if (p == NULL) {
        return NULL;
    }

    // Check if we switched pools.
    if (t_cache.pool != p) {
        flush_all_local_cache();
        t_cache.pool = p;
        t_cache.count = 0;
    }

    // Fast path: allocate from local cache.
    // Most allocations should hit this path.
    if (t_cache.count > 0) {
        return t_cache.items[--t_cache.count];
    }

    // Slow path: cache is empty, refill from global pool.
    // This uses atomic CAS operations, once every BULK_TRANSFER_SIZE.
    refill_local_cache(p);

    // Retry again after refill.
    if (t_cache.count > 0) {
        return t_cache.items[--t_cache.count];
    }

    // Global pool is also empty (all buffers are in use).
    return NULL;
}

void pktbuf_free(pktbuf_pool_t *p, pktbuf_t *buf) {
    if (p == NULL || buf == NULL) {
        return;
    }

    buf->len = 0;

    // Check if we switched pools.
    if (t_cache.pool != p) {
        flush_all_local_cache();
        t_cache.pool = p;
        t_cache.count = 0;
    }

    // Fast path: free to the local cache.
    // Most frees should hit this path.
    if (t_cache.count < LOCAL_CACHE_SIZE) {
        t_cache.items[t_cache.count++] = buf;
        return;
    }

    // Slow path: cache is full, flush BULK_TRANSFER_SIZE to global pool.
    flush_local_cache(p);

    // Now there's space in the cache. Add buffer to local cache.
    t_cache.items[t_cache.count++] = buf;
}