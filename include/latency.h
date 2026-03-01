#ifndef LATENCY_H
#define LATENCY_H

#include <stdint.h>

static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ __volatile__(
        "lfence\n\t" /* Wait for prior instructions to complete */
        "rdtsc"      /* Read TSC: EDX:EAX = cycle counter */
        : "=a"(lo),  /* Output: EAX (lower 32 bits) -> lo */
          "=d"(hi)   /* Output: EDX (upper 32 bits) -> hi */
        :            /* No inputs */
        : "memory"   /* Clobber: tell compiler memory may have changed,
                        preventing it from reordering this asm across
                        memory operations */
    );
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

#define LATENCY_NUM_BUCKETS 8

typedef struct {
    uint64_t buckets[LATENCY_NUM_BUCKETS];
    uint64_t total_count;
    uint64_t min_ns;
    uint64_t max_ns;
    uint64_t sum_ns;
} latency_histogram_t;

static const uint64_t latency_bucket_bounds[LATENCY_NUM_BUCKETS] = {
    100, /* Bucket 0: < 100 ns (L1/L2 cache hits) */
    500, /* Bucket 1: < 500 ns (typical fast-path processing) */
    1000, /* Bucket 2: < 1 us (cache misses or branch mispredicts) */
    5000, /* Bucket 3: < 5 us (TLB miss, or contention on global pool) */
    10000, /* Bucket 4: < 10 us (cross-NUMA access or scheduling jitter) */
    50000, /* Bucket 5: < 50 us (context switch or interrupt) */
    100000, /* Bucket 6: < 100 us (something went wrong) */
    UINT64_MAX /* Bucket 7: >= 100 us (catch-all, everything will fit here) */
};

/* How many TSC cycles correspond to one nanosecond. */
double latency_calibrate_tsc(void);

/*
    Initialize a histogram to zero state.
    Sets min_ns to UINT64_MAX => first sample becomes the new min.
*/
void latency_histogram_init(latency_histogram_t *h);

/*
    Record a single latency sample.
    Increment the corresponding latency bucket's counter.
*/
void latency_record(latency_histogram_t *h, uint64_t cycles, double cycles_per_ns);

/*
    Compute a percentile from the histogram.
        Returns upper bound (in ns) of the bucket that contains the requested percentile.
*/
uint64_t latency_percentile(const latency_histogram_t *h, double percentile);

/*
    Merge histogram 'src' into 'dst.
    Not thread-safe, caller to make sure no writer is active on src.
*/
void latency_histogram_merge(latency_histogram_t *dst, const latency_histogram_t *src);

#endif