#define _POSIX_C_SOURCE 199309L

#include "latency.h"

#include <string.h>
#include <time.h>

/* Measure how many CPU TSC cycles correspond to one nanosecond of wall time. */
double latency_calibrate_tsc(void) {
    struct timespec ts_start, ts_end;

    /* Snapshot wall clock and TSC before sleeping */
    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    uint64_t tsc_start = rdtsc();

    /* Sleep ~50ms to get a measurable interval */
    struct timespec sleep_time = {.tv_sec = 0, .tv_nsec = 50000000};
    nanosleep(&sleep_time, NULL);

    /* Snapshot again after waking */
    uint64_t tsc_end = rdtsc();
    clock_gettime(CLOCK_MONOTONIC, &ts_end);

    /* Convert timespec to flat nanosecond values */
    uint64_t ns_start = (uint64_t)ts_start.tv_sec * 1000000000ULL + (uint64_t)ts_start.tv_nsec;
    uint64_t ns_end = (uint64_t)ts_end.tv_sec * 1000000000ULL + (uint64_t)ts_end.tv_nsec;

    uint64_t delta_ns = ns_end - ns_start;
    uint64_t delta_tsc = tsc_end - tsc_start;

    /* Return the conversion factor: cycles per nanosecond */
    return (double)delta_tsc / (double)delta_ns;
}

void latency_histogram_init(latency_histogram_t *h) {
    memset(h, 0, sizeof(*h));
    h->min_ns = UINT64_MAX;
}

/* Record a single latency sample (in TSC cycles) into the histogram. */
void latency_record(latency_histogram_t *h, uint64_t cycles, double cycles_per_ns) {
    uint64_t ns = (uint64_t)((double)cycles / cycles_per_ns);

    /* Walk bucket bounds to find where this sample lands */
    int bucket = LATENCY_NUM_BUCKETS - 1; /* Default is the catch-all bucket */
    for (int i = 0; i < LATENCY_NUM_BUCKETS; i++) {
        if (ns < latency_bucket_bounds[i]) {
            bucket = i;
            break;
        }
    }

    h->buckets[bucket]++;
    h->total_count++;
    h->sum_ns += ns;

    if (ns < h->min_ns) h->min_ns = ns;
    if (ns > h->max_ns) h->max_ns = ns;
}

uint64_t latency_percentile(const latency_histogram_t *h, double percentile) {
    if (h->total_count == 0) return 0;

    /*  Number of samples that must fall at or below the target percentile */
    uint64_t target = (uint64_t)(percentile * (double)h->total_count);

    uint64_t cumulative = 0;
    for (int i = 0; i < LATENCY_NUM_BUCKETS; i++) {
        cumulative += h->buckets[i];
        if (cumulative >= target) {
            return latency_bucket_bounds[i];
        }
    }

    /* Should never reach here, because the last bucket is UINT64_MAX */
    return latency_bucket_bounds[LATENCY_NUM_BUCKETS - 1];
}

void latency_histogram_merge(latency_histogram_t *dst, const latency_histogram_t *src) {
    for (int i = 0; i < LATENCY_NUM_BUCKETS; i++) {
        dst->buckets[i] += src->buckets[i];
    }

    dst->total_count += src->total_count;
    dst->sum_ns += src->sum_ns;

    /* Keep the global min, max */
    if (src->min_ns < dst->min_ns) dst->min_ns = src->min_ns;
    if (src->max_ns > dst->max_ns) dst->max_ns = src->max_ns;
}