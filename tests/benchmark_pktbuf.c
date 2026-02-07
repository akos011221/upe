/*
    Measure the scalability of the lock-free packet buffer pool across multiple threads.

    Expected is to have near-line scaling (N threads = N * throughput). Thread-local cache should
    satisfy most of the alloc/free requests, thus bypassing the global lock-free pool.

    Usage:
        # Defaul: 4 threads, 50M ops/thread, pool=4096
        ./benchmark_pktbuf

        # Custom: 8 threads, 100M ops/thread, pool=4096, JSON out
        ./benchmark_pktbuf --threads=8 --ops=100000000 --pool-size=4096 --json

        # With warm-up
        ./benchmark_pktbuf --threads=4 --warmup
*/

#define _POSIX_C_SOURCE 199309L

#include "benchmark_test.h"
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
    size_t ops_to_perform; // How many ops this thread should do.
    int thread_id;

    // Results after thread is done:
    size_t ops_completed; // Op done (=ops_to_perform).
    double duration_sec;  // Wall-clock time for the thread.
    double ops_per_sec;
} worker_ctx_t;

/*
    Worker thread function.
*/

static void *worker_thread(void *arg) {
    worker_ctx_t *ctx = (worker_ctx_t *)arg;
    size_t completed = 0; // Local variable in CPU register to avoid sharing.

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
            completed++;
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
    ctx->ops_completed = completed;
    ctx->duration_sec = end - start;
    ctx->ops_per_sec = (double)ctx->ops_completed / ctx->duration_sec;

    return NULL;
}

/*
    Warm-up function.

    Populate the CPU caches and train branch predictor.
    Runs each thread for ~1s.

    - Populate L1/L2/L3 caches with pool metadata
    - Train branch predictor for alloc/free code paths
    - Fills TLBs (translation lookaside buffers) with page mappings

    Why?
    - First iteration: cache cold = bigger latency
    - Steady state: cache warm = much lower latency
    - We only care about steady state.
*/
static void warmup_phase(pktbuf_pool_t *pool, int num_threads) {
    printf("Warming up (%d threads)...\n", num_threads);

    pthread_t *threads = malloc(sizeof(pthread_t) * (size_t)num_threads);
    worker_ctx_t *contexts = malloc(sizeof(worker_ctx_t) * (size_t)num_threads);

    // Run warm-up for 1 million ops per thread.
    size_t warmup_ops = 1000000;

    for (int i = 0; i < num_threads; i++) {
        contexts[i].pool = pool;
        contexts[i].ops_to_perform = warmup_ops;
        contexts[i].thread_id = i;
        contexts[i].ops_completed = 0;

        pthread_create(&threads[i], NULL, worker_thread, &contexts[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    free(contexts);

    printf("Warm-up done.\n");
}

// Benchmark run functions.

typedef struct {
    double total_duration_sec; // Wall-clock time (longest thread).
    double total_ops_per_sec;  // Total throughput across all threads.
    double mean_thread_tput;   // Mean per-thread throughput.
    double cv;                 // Coefficient of variation (load balance).
} benchmark_result_t;

static benchmark_result_t run_benchmark(const bench_config_t *cfg) {
    // Pool sizing must be:
    // LOCAL_CACHE_SIZE(64) * num_threads with headroom.
    // Headroom, because there can be imbalance, some threads allocate more,
    // than others.
    pktbuf_pool_t pool;
    pktbuf_pool_init(&pool, cfg->pool_capacity);

    if (cfg->warmup) {
        warmup_phase(&pool, cfg->num_threads);
    }

    pthread_t *threads = malloc(sizeof(pthread_t) * (size_t)cfg->num_threads);
    worker_ctx_t *contexts = malloc(sizeof(worker_ctx_t) * (size_t)cfg->num_threads);

    for (int i = 0; i < cfg->num_threads; i++) {
        contexts[i].pool = &pool;
        contexts[i].ops_to_perform = cfg->ops_per_thread;
        contexts[i].thread_id = i;
        contexts[i].ops_completed = 0;
        contexts[i].duration_sec = 0.0;
        contexts[i].ops_per_sec = 0.0;
    }

    double start = benchmark_get_time();

    for (int i = 0; i < cfg->num_threads; i++) {
        pthread_create(&threads[i], NULL, worker_thread, &contexts[i]);
    }

    for (int i = 0; i < cfg->num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    double end = benchmark_get_time();

    // Results.
    benchmark_result_t result;
    result.total_duration_sec = end - start;

    size_t total_ops = 0;
    double *thread_tputs = malloc(sizeof(double) * (size_t)cfg->num_threads);

    for (int i = 0; i < cfg->num_threads; i++) {
        total_ops += contexts[i].ops_completed;
        thread_tputs[i] = contexts[i].ops_per_sec;
    }

    result.total_ops_per_sec = (double)total_ops / result.total_duration_sec;

    benchmark_calculate_variance(thread_tputs, cfg->num_threads, &result.mean_thread_tput,
                                 &result.cv);

    // Cleanup.
    free(thread_tputs);
    free(threads);
    free(contexts);
    pktbuf_pool_destroy(&pool);

    return result;
}

/*
    Output functions.
*/

static void output_human(const bench_config_t *cfg, const benchmark_result_t *single,
                         const benchmark_result_t *multi, double overhead_ns) {
    printf("=-> Packet Buffer Contention Benchmark <-=\n");

    printf("Settings:\n");
    printf("    Threads:    %d\n", cfg->num_threads);
    printf("    Ops/Thread: %zu\n", cfg->ops_per_thread);
    printf("    Pool Size:  %zu buffers\n", cfg->pool_capacity);
    printf("    Warm-up:    %s\n", cfg->warmup ? "Yes" : "No");
    printf("    Timing overhead   %.1f ns\n\n", overhead_ns);

    printf("Results:\n");
    printf("    Single Thread:\n");
    printf("    Throughput: %.2f M ops/sec\n", single->total_ops_per_sec / 1e6);
    printf("    Duration:   %.4f s\n", single->total_duration_sec);
    printf("    Load balance (CV): %.4f (%.1f%%)\n", multi->cv, multi->cv * 100.0);
    printf("\n");

    double scaling_factor = multi->total_ops_per_sec / single->total_ops_per_sec;
    double efficiency = (scaling_factor / (double)cfg->num_threads) * 100.0;

    printf("Analysis:\n");
    printf("    Scaling factor: %.2fx (Ideal: %.2fx)\n", scaling_factor, (double)cfg->num_threads);
    printf("    Efficiency:     %.2f%%\n", efficiency);

    if (efficiency >= 90.0) {
        printf("    Excellent scaling.\n");
    } else if (efficiency >= 70.0) {
        printf("    Good scaling.\n");
    } else {
        printf("    Poor scaling.\n");
    }
}

static void output_json(const bench_config_t *cfg, const benchmark_result_t *single,
                        const benchmark_result_t *multi, double overhead_ns, FILE *out) {
    system_info_t sysinfo;
    benchmark_get_system_info(&sysinfo);

    json_ctx_t ctx;
    json_init(&ctx, out);

    json_begin_object(&ctx);

    json_key_string(&ctx, "benchmark", "pktbuf_contention");

    // System info.
    json_begin_nested_object(&ctx, "system_info");
    json_key_string(&ctx, "cpu_model", sysinfo.cpu_model);
    json_key_int(&ctx, "num_cores", sysinfo.num_cores);
    json_key_int(&ctx, "l1d_cache_kb", sysinfo.l1d_cache_kb);
    json_key_int(&ctx, "l2_cache_kb", sysinfo.l2_cache_kb);
    json_key_int(&ctx, "l3_cache_kb", sysinfo.l3_cache_kb);
    json_key_int(&ctx, "numa_nodes", sysinfo.numa_nodes);
    json_end_object(&ctx);

    // Config.
    json_begin_nested_object(&ctx, "config");
    json_key_int(&ctx, "num_threads", cfg->num_threads);
    json_key_int(&ctx, "ops_per_thread", (int64_t)cfg->ops_per_thread);
    json_key_int(&ctx, "pool_capacity", (int64_t)cfg->pool_capacity);
    json_key_bool(&ctx, "warmup", cfg->warmup);
    json_end_object(&ctx);

    // Results.
    json_begin_nested_object(&ctx, "results");

    json_begin_nested_object(&ctx, "single_thread");
    json_key_double(&ctx, "ops_per_sec", single->total_ops_per_sec);
    json_key_double(&ctx, "duration_sec", single->total_duration_sec);
    json_end_object(&ctx);

    json_begin_nested_object(&ctx, "multi_thread");
    json_key_int(&ctx, "threads", cfg->num_threads);
    json_key_double(&ctx, "ops_per_sec", multi->total_ops_per_sec);
    json_key_double(&ctx, "duration_sec", multi->total_duration_sec);
    json_key_double(&ctx, "mean_thread_ops_per_sec", multi->mean_thread_tput);
    json_key_double(&ctx, "coefficient_of_variation", multi->cv);

    double scaling_factor = multi->total_ops_per_sec / single->total_ops_per_sec;
    json_key_double(&ctx, "scaling_factor", scaling_factor);
    json_key_double(&ctx, "efficiency_percent",
                    (scaling_factor / (double)cfg->num_threads) * 100.0);
    json_end_object(&ctx);

    json_key_double(&ctx, "measurement_overhead_ns", overhead_ns);

    json_end_object(&ctx); // Results.

    json_end_object(&ctx); // Root.
    fprintf(out, "\n");
}

/*
    Main.
*/

static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("    -t, --threads=N     Number of threads (default: 4)\n");
    printf("    -n, --ops=N         Operations per thread (default: 50000000)\n");
    printf("    -p, --pool-size=N   Pool capacity (default: 4096)\n");
    printf("    -w, --warmup        Enable warm-up-phase\n");
    printf("    -j, --json          Output JSON format\n");
    printf("    -o, --output-FILE   Write to file instead of stdout\n");
    printf("    -h, --help          Show this help\n\n");
    printf("Examples:\n");
    printf("    %s --threads=8 --ops=100000000\n", prog);
    printf("    %s --threads=4  --warmup --json > out.json\n", prog);
}

int main(int argc, char **argv) {
    bench_config_t cfg = default_config();

    static struct option long_options[] = {{"threads", required_argument, NULL, 't'},
                                           {"ops", required_argument, NULL, 'n'},
                                           {"pool-size", required_argument, NULL, 'p'},
                                           {"warmup", no_argument, NULL, 'w'},
                                           {"json", no_argument, NULL, 'j'},
                                           {"output", required_argument, NULL, 'o'},
                                           {"help", no_argument, NULL, 'h'},
                                           {NULL, 0, NULL, 0}

    };

    int opt;
    while ((opt = getopt_long(argc, argv, "t:n:p:wjo:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 't':
            cfg.num_threads = benchmark_parse_int("threads");
            if (cfg.num_threads <= 0) {
                fprintf(stderr, "Error: threads must be > 0\n");
                return EXIT_FAILURE;
            }
            break;
        case 'n':
            cfg.ops_per_thread = benchmark_parse_size_t("ops");
            if (cfg.ops_per_thread == 0) {
                fprintf(stderr, "Error: ops must be > 0\n");
                return EXIT_FAILURE;
            }
            break;
        case 'p':
            cfg.pool_capacity = benchmark_parse_size_t("pool-size");
            if (cfg.pool_capacity == 0) {
                fprintf(stderr, "Error: pool-size must be > 0\n");
                return EXIT_FAILURE;
            }
            break;
        case 'w':
            cfg.warmup = true;
            break;
        case 'j':
            cfg.json_output = true;
            break;
        case 'o':
            cfg.output_file = optarg;
            break;
        case 'h':
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    // Measure timing overhead.
    double overhead_ns = benchmark_measure_timing_overhead();

    // Single-threaded baseline.
    bench_config_t single_cfg = cfg;
    single_cfg.num_threads = 1;
    benchmark_result_t single = run_benchmark(&single_cfg);

    // Multi-threaded test.
    benchmark_result_t multi = run_benchmark(&cfg);

    // Output.
    FILE *out = stdout;
    if (cfg.output_file) {
        out = fopen(cfg.output_file, "w");
        if (!out) {
            perror("fopen");
            return EXIT_FAILURE;
        }
    }

    if (cfg.json_output) {
        output_json(&cfg, &single, &multi, overhead_ns, out);
    } else {
        output_human(&cfg, &single, &multi, overhead_ns);
    }

    if (cfg.output_file) {
        fclose(out);
    }

    return EXIT_SUCCESS;
}