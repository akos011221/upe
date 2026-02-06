/*
    Measure the scalability of the lock-free packet buffer pool across multiple threads.

    Expected is to have near-line scaling (N threads = N * throughput). Thread-local cache should
    satisfy most of the alloc/free requests, thus bypassing the global lock-free pool.

    Usage:
        # Defaul: 4 threads, 50M ops/thread, pool=64
        ./benchmark_pktbuf

        # Custom: 8 threads, 100M ops/thread, pool=4096, JSON out
        ./benchmark_pktbuf --threads=8 --ops=100000000 --pool-size=4096 --json

        # With warm-up
        ./benchmark_pktbuf --threads=4 --warmup
*/

#define _POSIX_C_SOURCE 199309L

#include "benchmark.h"
#include "pktbuf.h"

#include <getopt.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
    Config.
*/

typedef struct {
    int num_threads;         // Number of worker threads.
    size_t ops_per_thread;   // Alloc/free ops per thread.
    size_t pool_capacity;    // Total buffers in global pool.
    bool warmup;             // Enable warm-up phase.
    bool json_output;        // Enable JSON output.
    const char *output_file; // NULL = stdout, otherwise write to file.
} bench_config_t;

// Default config.
static bench_config_t default_config(void) {
    bench_config_t cfg;
    cfg.num_threads = 4;
    cfg.ops_per_thread = 50000000;
    cfg.pool_capacity = 4096;
    cfg.warmup = false;
    cfg.json_output = false;
    cfg.output_file = NULL;
    return cfg;
}

// Per-thread context.
typedef struct {
    pktbuf_pool_t *pool;   // Shared pool.
    size_t ops_to_perform; // What operation this thread should do.
    int thread_id;

    // Results after thread is done:
    size_t ops_completed; // Op done (=ops_to_perform).
    double duration_sec;  // Wall-clock time for the thread.
    double ops_per_sec;
} worker_ctx_t;

/*
    Worker thread func.
*/

static void *worker_thread(void *arg) {
    worker_ctx_t *ctx = (worker_ctx_t *)arg;

    double start = benchmark_get_time();

    // Alloc buffer, simulate using its data, then free it.
    for (size_t i = 0; i < ctx->ops_to_perform; i++) {
        pktbuf_t *b = pktbuf_alloc(ctx->pool);
        if (b) {
            /*
                Use 'volatile' to prevent the compiler from optimizing away this write.
                Without it, the Dead Code Elimination(DCE) pass would see that the buffer is freed
                immediately without being read, and skip the write entirely. This ensures the CPU
                actually touches the memory, pulling it into the L1 cache.
            */
            volatile uint8_t *data = b->data;
            data[0] = (uint8_t)(i & 0xFF);

            pktbuf_free(ctx->pool, b);
            ctx->ops_completed++;
        } else {
            // Pool exhausted.
            // Should be: (pool_capacity >= num_threads * LOCAL_CACHE_SIZE).
            fprintf(stderr,
                    "WARNING: Thread %d: pktbuf_alloc() returned NULL "
                    "(pool exhausted)\n",
                    ctx->thread_id);
        }
    }

    double end = benchmark_get_time();
    ctx->duration_sec = end - start;
    ctx->ops_per_sec = (double)ctx->ops_completed / ctx->duration_sec;

    return NULL;
}
