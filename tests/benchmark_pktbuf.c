/*
    Benchmark Packet Buffer lock contention.

    This benchmark measures the overhead of the memory pool's locking mechanism
    when multiple threads accessing it in the same time.

    Relevance:
    It was originally designed to see bottleneck of the shared global lock in the
    packet buffer pool. Since then thread-local caching has been implemented, this
    test now verifies that the contention is gone.

    The scaling should be near-linear now (4x throughput with 4 threads).
    It's because the benchmark keeps the cache in a "sweet spot" (it's neither empty
    or full) => almost all packet alloc/free requests are satisfied by the thread-local
    cache, bypassing the global mutex.
*/

#define _POSIX_C_SOURCE 199309L // clock_gettime
#include "pktbuf.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Number of alloc/free pairs per thread
#define OPS_PER_THREAD 50000000

pktbuf_pool_t g_pool;

void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < OPS_PER_THREAD; i++) {
        pktbuf_t *b = pktbuf_alloc(&g_pool);
        if (b) {
            pktbuf_free(&g_pool, b);
        }
    }
    return NULL;
}

double run_benchmark(int num_threads) {
    pthread_t *threads = malloc(sizeof(pthread_t) * (size_t)num_threads);

    // Overprovision the pool to avoid starvation due to scheduling skew.
    // 16 buffers per thread is a conservative burst depth.
    pktbuf_pool_init(&g_pool, (size_t)(num_threads * 16));

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, worker, NULL);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    pktbuf_pool_destroy(&g_pool);
    free(threads);

    double seconds =
        (double)(end.tv_sec - start.tv_sec) + (double)(end.tv_nsec - start.tv_nsec) / 1e9;
    return seconds;
}

int main(void) {
    printf("=-> Packet Buffer Lock Contention Benchmark <-=\n");

    // 1) Baseline: Single Thread
    double t1 = run_benchmark(1);
    double ops1 = OPS_PER_THREAD / t1;
    printf("1 Thread:   %8.0f ops/sec (%.4f s)\n", ops1, t1);

    // 2) Contention: 4 Threads
    // Total operations = 4 * OPS_PER_THREAD
    double t4 = run_benchmark(4);
    double ops4 = (4 * OPS_PER_THREAD) / t4;
    printf("4 Threads:  %8.0f ops/sec (%.4f s)\n", ops4, t4);

    // 3) Analysis
    printf("-----------------------------------------------\n");
    printf("Scaling Factor: %.2fx (Ideal: 4.00x)\n", ops4 / ops1);
    return 0;
}