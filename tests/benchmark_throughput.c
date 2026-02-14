/*
    Benchmark e2e throughput.

    This benchmark measures the maximum processing speed of UPE. It removes the network hardware
    from the picture by creating a __Synthetic NIC__ (main thread) that generates packets in memory
    and pushes them into SPSC ring buffers.
*/

#define _POSIX_C_SOURCE 200809L

#include "arp_table.h"
#include "benchmark_test.h"
#include "ndp_table.h"
#include "pktbuf.h"
#include "ring.h"
#include "rule_table.h"
#include "tx.h"
#include "worker.h"

#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

volatile sig_atomic_t g_stop = 0;

/* Dummy implementation of tx_send and tx_send_batch for worker: */
int tx_send(const tx_ctx_t *tx, const uint8_t *frame, size_t len) {
    (void)tx;
    (void)frame;
    (void)len;
    return 0;
}
int tx_send_batch(const tx_ctx_t *tx, const uint8_t *const *frames, const size_t *lens, int count) {
    (void)tx;
    (void)frames;
    (void)lens;
    return count;
}

#define MAX_BATCH_SIZE 256
#define MAX_WORKERS 16

/* ── Config ───────────────────────────────────────────────────────── */

typedef struct {
    int duration_sec;
    int num_workers;
    size_t pool_capacity;
    size_t ring_size;
    int batch_size;
    int packet_size;
    bool warmup;
    bool json_output;
    const char *output_file;
} bench_config_t;

static bench_config_t default_config(void) {
    bench_config_t cfg;
    cfg.duration_sec = 10;
    cfg.num_workers = 1;
    cfg.pool_capacity = 8192;
    cfg.ring_size = 1024;
    cfg.batch_size = 32;
    cfg.packet_size = 64;
    cfg.warmup = false;
    cfg.json_output = false;
    cfg.output_file = NULL;
    return cfg;
}

/* ── Environment (shared) ─────────────────────────────────────────── */

typedef struct {
    pktbuf_pool_t pool;
    spsc_ring_t *rings;
    rule_table_t rt;
    arp_table_t arpt;
    ndp_table_t ndpt;
    tx_ctx_t tx;
    worker_t *workers;
} bench_env_t;

static int setup_env(bench_env_t *env, const bench_config_t *cfg) {
    pktbuf_pool_init(&env->pool, cfg->pool_capacity);

    env->rings = malloc(sizeof(spsc_ring_t) * (size_t)cfg->num_workers);
    for (int i = 0; i < cfg->num_workers; i++) {
        ring_init(&env->rings[i], cfg->ring_size);
    }

    rule_table_init(&env->rt, 1024);
    rule_t r = {.priority = 10, .protocol = 6, .action = {.type = ACT_FWD, .out_ifindex = 1}};
    rule_table_add(&env->rt, &r);

    arp_table_init(&env->arpt, 1024);
    uint32_t dst_ip = (10U << 24) | (128U << 16) | (0U << 8) | 2U;
    uint8_t dst_mac[6] = {0xaa, 0x00, 0x00, 0x00, 0x00, 0xbb};
    arp_update(&env->arpt, dst_ip, dst_mac);

    ndp_table_init(&env->ndpt, 1024);

    memset(&env->tx, 0, sizeof(env->tx));
    env->tx.eth_addr[5] = 0xbb;

    env->workers = malloc(sizeof(worker_t) * (size_t)cfg->num_workers);
    for (int i = 0; i < cfg->num_workers; i++) {
        worker_init(&env->workers[i], i, -1, &env->rings[i], &env->pool, &env->rt, &env->tx,
                    &env->arpt, &env->ndpt);
    }

    return 0;
}

static void teardown_env(bench_env_t *env, int num_workers) {
    for (int i = 0; i < num_workers; i++) {
        worker_destroy(&env->workers[i]);
    }
    free(env->workers);

    pktbuf_pool_destroy(&env->pool);

    for (int i = 0; i < num_workers; i++) {
        ring_destroy(&env->rings[i]);
    }
    free(env->rings);

    rule_table_destroy(&env->rt);
    arp_table_destroy(&env->arpt);
    ndp_table_destroy(&env->ndpt);
}

/* ── Packet Builder ───────────────────────────────────────────────── */

static void build_dummy_packet(pktbuf_t *b, int packet_size) {
    /* Eth (14) + IP (20) + TCP (20) = 54 bytes + rest are zero-padded. */
    b->len = (size_t)packet_size;
    uint8_t *p = b->data;
    memset(p, 0, (size_t)packet_size);

    /* Ethernet header (14 bytes). */
    p[12] = 0x08; // EtherType part 1.
    p[13] = 0x00; // EtherType part 2.

    /* IPv4 header (20 bytes). */
    p += 14;
    p[0] = 0x45;                                 // Version 4, IHL 5.
    p[2] = (uint8_t)((packet_size - 14) >> 8);   // Total Length high.
    p[3] = (uint8_t)((packet_size - 14) & 0xFF); // Total Length low.
    p[8] = 64;                                   // TTL.
    p[9] = 6;                                    // Protocol = TCP.
    /* Src: 10.128.0.1 */
    p[12] = 10;
    p[13] = 128;
    p[14] = 0;
    p[15] = 1;
    /* Dst: 10.128.0.2 */
    p[16] = 10;
    p[17] = 128;
    p[18] = 0;
    p[19] = 2;

    /* TCP header (20 bytes). */
    p += 20;
    // Src port: 45000
    p[0] = 0xAF;
    p[1] = 0xC8;
    // Dst port: 80
    p[2] = 0x00;
    p[3] = 0x50;
    p[12] = 0x50; // Data offset: 5 words (20 bytes).
}

/* ── Producer Loop ────────────────────────────────────────────────── */

/*
    Producer: allocate -> build packet -> push for `seconds` seconds.
*/
typedef struct {
    uint64_t packets_pushed;
    uint64_t ring_full_events;
    double duration_sec;
} producer_result_t;

static producer_result_t run_producer(const bench_config_t *cfg, pktbuf_pool_t *pool,
                                      spsc_ring_t *rings, double seconds) {
    producer_result_t result = {0};
    void *batch[MAX_BATCH_SIZE];
    int ring_idx = 0;
    int check_counter = 0;

    double start = benchmark_get_time();
    double deadline = start + seconds;
    double now = start;

    while (now < deadline) {
        int actual = 0;
        for (int i = 0; i < cfg->batch_size; i++) {
            pktbuf_t *b = pktbuf_alloc(pool);
            if (!b) break;
            build_dummy_packet(b, cfg->packet_size);
            batch[actual++] = b;
        }

        if (actual == 0) {
            /* Pool is empty, wait for workers to free buffers. */
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 1000};
            nanosleep(&ts, NULL);
            now = benchmark_get_time();
            check_counter = 0;
            continue;
        }

        unsigned int pushed = ring_push_burst(&rings[ring_idx], batch, (unsigned int)actual);
        result.packets_pushed += pushed;

        if (pushed < (unsigned int)actual) {
            result.ring_full_events++;
            for (unsigned int i = pushed; i < (unsigned int)actual; i++) {
                pktbuf_free(pool, batch[i]);
            }
        }

        ring_idx = (ring_idx + 1) % cfg->num_workers;

        /* Check time every 128 batches to keep overhead smaller. */
        if (++check_counter >= 128) {
            now = benchmark_get_time();
            check_counter = 0;
        }
    }

    result.duration_sec = benchmark_get_time() - start;
    return result;
}

/* ── Result ───────────────────────────────────────────────────────── */

typedef struct {
    producer_result_t producer;
    uint64_t per_worker_pkts[MAX_WORKERS];
    int num_workers;
} bench_result_t;

/* ── Output ───────────────────────────────────────────────────────── */

static void output_human(const bench_config_t *cfg, const bench_result_t *res, double overhead_ns) {
    double dur = res->producer.duration_sec;
    double push_mpps = ((double)res->producer.packets_pushed / dur) / 1e6;

    printf("=-> UPE e2e Throughput Benchmark <-=\n");

    printf("Settings:\n");
    printf("    Duration:    %d s\n", cfg->duration_sec);
    printf("    Workers:     %d\n", cfg->num_workers);
    printf("    Pool Size:   %zu buffers\n", cfg->pool_capacity);
    printf("    Ring Size:   %zu per worker\n", cfg->ring_size);
    printf("    Batch Size:  %d\n", cfg->batch_size);
    printf("    Packet Size: %d bytes\n", cfg->packet_size);
    printf("    Warm-up:     %s\n", cfg->warmup ? "Yes" : "No");
    printf("    Timing overhead: %.1f ns\n\n", overhead_ns);

    printf("Producer:\n");
    printf("    Packets Pushed: %lu\n", (unsigned long)res->producer.packets_pushed);
    printf("    Throughput:   %.2f Mpps\n", push_mpps);
    printf("    Ring Full Events: %lu\n\n", (unsigned long)res->producer.ring_full_events);

    uint64_t total_consumed = 0;
    printf("Consumer (per worker):\n");
    for (int i = 0; i < cfg->num_workers; i++) {
        total_consumed += res->per_worker_pkts[i];
        double wmpps = ((double)res->per_worker_pkts[i] / dur) / 1e6;
        printf("    Worker %d: %lu packets (%.2f Mpps)\n", i,
               (unsigned long)res->per_worker_pkts[i], wmpps);
    }

    double consume_mpps = ((double)total_consumed / dur) / 1e6;
    printf("\nTotals:\n");
    printf("    Consumer Throughput: %.2f Mpps\n", consume_mpps);
    printf("    Time Elapsed:        %.4f s\n", dur);

    // Backpressure analysis.
    printf("\nAnalysis:\n");
    if (res->producer.ring_full_events > 0) {
        double full_percent =
            ((double)res->producer.ring_full_events /
             (double)(res->producer.packets_pushed + res->producer.ring_full_events)) *
            100.0;
        printf("    Ring backpressure: %.1f%% of pushes hit a full ring.\n", full_percent);
        if (full_percent > 10.0) {
            printf("    -> Consumer is the bottleneck.\n");
        }
    } else {
        printf("    No ring backpressure (producer never blocked).\n");
    }
}

static void output_json(const bench_config_t *cfg, const bench_result_t *res, double overhead_ns,
                        FILE *out) {
    system_info_t sysinfo;
    benchmark_get_system_info(&sysinfo);

    json_ctx_t ctx;
    json_init(&ctx, out);
    json_begin_object(&ctx);

    double dur = res->producer.duration_sec;

    json_key_string(&ctx, "benchmark", "e2e_throughput");

    /* System info. */
    json_begin_nested_object(&ctx, "system_info");
    json_key_string(&ctx, "cpu_model", sysinfo.cpu_model);
    json_key_int(&ctx, "num_cores", sysinfo.num_cores);
    json_key_int(&ctx, "l1d_cache_kb", sysinfo.l1d_cache_kb);
    json_key_int(&ctx, "l2_cache_kb", sysinfo.l2_cache_kb);
    json_key_int(&ctx, "l3_cache_kb", sysinfo.l3_cache_kb);
    json_key_int(&ctx, "numa_nodes", sysinfo.numa_nodes);
    json_end_object(&ctx);

    /* Config. */
    json_begin_nested_object(&ctx, "config");
    json_key_int(&ctx, "duration_sec", cfg->duration_sec);
    json_key_int(&ctx, "num_workers", cfg->num_workers);
    json_key_int(&ctx, "pool_capacity", (int64_t)cfg->pool_capacity);
    json_key_int(&ctx, "ring_size", (int64_t)cfg->ring_size);
    json_key_int(&ctx, "batch_size", cfg->batch_size);
    json_key_int(&ctx, "packet_size", cfg->packet_size);
    json_key_bool(&ctx, "warmup", cfg->warmup);
    json_end_object(&ctx);

    /* Results. */
    json_begin_nested_object(&ctx, "results");

    json_begin_nested_object(&ctx, "producer");
    json_key_int(&ctx, "packets_pushed", (int64_t)res->producer.packets_pushed);
    json_key_double(&ctx, "throughput_mpps", ((double)res->producer.packets_pushed / dur) / 1e6);
    json_key_int(&ctx, "ring_full_events", (int64_t)res->producer.ring_full_events);
    json_key_double(&ctx, "duration_sec", dur);
    json_end_object(&ctx);

    json_begin_nested_object(&ctx, "consumer");

    uint64_t total_consumed = 0;
    for (int i = 0; i < cfg->num_workers; i++) {
        total_consumed += res->per_worker_pkts[i];
    }

    json_key_int(&ctx, "total_packets_processed", (int64_t)total_consumed);
    json_key_double(&ctx, "throughput_mpps", ((double)total_consumed / dur) / 1e6);

    for (int i = 0; i < cfg->num_workers; i++) {
        char key[32];
        snprintf(key, sizeof(key), "worker_%d", i);
        json_begin_nested_object(&ctx, key);
        json_key_int(&ctx, "packets_in", (int64_t)res->per_worker_pkts[i]);
        json_key_double(&ctx, "throughput_mpps", ((double)res->per_worker_pkts[i] / dur) / 1e6);
        json_end_object(&ctx);
    }

    json_end_object(&ctx); /* consumer */

    json_key_double(&ctx, "measurement_overhead_ns", overhead_ns);

    json_end_object(&ctx); /* results */

    json_end_object(&ctx); /* root */
    fprintf(out, "\n");
}

/* ── CLI ──────────────────────────────────────────────────────────── */

static bool is_power_of_two(size_t n) {
    return n != 0 && ((n & (n - 1)) == 0);
}

static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("    -d, --duration=N    Duration in seconds (default: 10)\n");
    printf("    -w, --workers=N     Number of worker threads (default: 1)\n");
    printf("    -p, --pool-size=N   Pool capacity (default: 8192)\n");
    printf("    -r, --ring-size=N   Ring size per worker, power of 2 (default: 1024)\n");
    printf("    -b, --batch-size=N  Batch size for push/pop (default: 32, max: 256)\n");
    printf("    -s, --packet-size=N Packet size in bytes, min 54 (default: 64)\n");
    printf("    -W, --warmup        Enable warm-up phase\n");
    printf("    -j, --json          Output JSON format\n");
    printf("    -o, --output=FILE   Write to file instead of stdout\n");
    printf("    -h, --help          Show this help\n\n");
    printf("Examples:\n");
    printf("    %s --workers=2 --duration=30 --batch-size=64\n", prog);
    printf("    %s --warmup --json > out.json\n", prog);
}

static int parse_args(int argc, char **argv, bench_config_t *cfg) {
    static struct option long_options[] = {{"duration", required_argument, NULL, 'd'},
                                           {"workers", required_argument, NULL, 'w'},
                                           {"pool-size", required_argument, NULL, 'p'},
                                           {"ring-size", required_argument, NULL, 'r'},
                                           {"batch-size", required_argument, NULL, 'b'},
                                           {"packet-size", required_argument, NULL, 's'},
                                           {"warmup", no_argument, NULL, 'W'},
                                           {"json", no_argument, NULL, 'j'},
                                           {"output", required_argument, NULL, 'o'},
                                           {"help", no_argument, NULL, 'h'},
                                           {NULL, 0, NULL, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "d:w:p:r:b:s:Wjo:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'd':
            cfg->duration_sec = benchmark_parse_int("duration");
            if (cfg->duration_sec <= 0) {
                fprintf(stderr, "Error: duration must be >0\n");
                return -1;
            }
            break;
        case 'w':
            cfg->num_workers = benchmark_parse_int("workers");
            if (cfg->num_workers <= 0 || cfg->num_workers > MAX_WORKERS) {
                fprintf(stderr, "Error: workers must be 1-%d\n", MAX_WORKERS);
                return -1;
            }
            break;
        case 'p':
            cfg->pool_capacity = benchmark_parse_size_t("pool-size");
            if (cfg->pool_capacity == 0) {
                fprintf(stderr, "Error: pool-size must be > 0\n");
                return -1;
            }
            break;
        case 'r':
            cfg->ring_size = benchmark_parse_size_t("ring-size");
            if (!is_power_of_two(cfg->ring_size)) {
                fprintf(stderr, "Error: ring-size must be a power of 2 (got %zu)\n",
                        cfg->ring_size);
                return -1;
            }
            break;
        case 'b':
            cfg->batch_size = benchmark_parse_int("batch-size");
            if (cfg->batch_size <= 0 || cfg->batch_size > MAX_BATCH_SIZE) {
                fprintf(stderr, "Error: batch-size must be 1-%d\n", MAX_BATCH_SIZE);
                return -1;
            }
            break;
        case 's':
            cfg->packet_size = benchmark_parse_int("packet-size");
            if (cfg->packet_size < 54) {
                fprintf(stderr, "Error: packet-size must be >= 54 (Eth+IP+TCP headers)\n");
                return -1;
            }
            if (cfg->packet_size > PKTBUF_DATA_SIZE) {
                fprintf(stderr, "Error: packet-size must be <= %d (PKTBUF_DATA_SIZE)\n",
                        PKTBUF_DATA_SIZE);
                return -1;
            }
            break;
        case 'W':
            cfg->warmup = true;
            break;
        case 'j':
            cfg->json_output = true;
            break;
        case 'o':
            cfg->output_file = optarg;
            break;
        case 'h':
            print_usage(argv[0]);
            exit(EXIT_SUCCESS);
        default:
            print_usage(argv[0]);
            return -1;
        }
    }
    return 0;
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    bench_config_t cfg = default_config();
    if (parse_args(argc, argv, &cfg) != 0) return EXIT_FAILURE;

    double overhead_ns = benchmark_measure_timing_overhead();

    /* Setup. */
    bench_env_t env;
    setup_env(&env, &cfg);

    for (int i = 0; i < cfg.num_workers; i++) {
        worker_start(&env.workers[i]);
    }

    /* Warm-up: run producer for 1s. */
    if (cfg.warmup) {
        printf("Warm-up start for 1s.\n");
        run_producer(&cfg, &env.pool, env.rings, 1.0);
        printf("Warm-up done.\n");
    }

    /* Snapshot worker counters before measure. */
    uint64_t pkts_in_before[MAX_WORKERS];
    for (int i = 0; i < cfg.num_workers; i++) {
        pkts_in_before[i] = env.workers[i].pkts_in;
    }

    if (!cfg.json_output) {
        printf("Benchmarking for %d seconds...\n", cfg.duration_sec);
    }

    /* Measurement. */
    bench_result_t result = {0};
    result.producer = run_producer(&cfg, &env.pool, env.rings, (double)cfg.duration_sec);
    result.num_workers = cfg.num_workers;
    for (int i = 0; i < cfg.num_workers; i++) {
        result.per_worker_pkts[i] = env.workers[i].pkts_in - pkts_in_before[i];
    }

    /* Stop workers. */
    g_stop = 1;
    for (int i = 0; i < cfg.num_workers; i++) {
        worker_join(&env.workers[i]);
    }

    /* Output. */
    FILE *out = stdout;
    if (cfg.output_file) {
        out = fopen(cfg.output_file, "w");
        if (!out) {
            perror("fopen");
            return EXIT_FAILURE;
        }
    }

    if (cfg.json_output) {
        output_json(&cfg, &result, overhead_ns, out);
    } else {
        output_human(&cfg, &result, overhead_ns);
    }

    if (cfg.output_file) fclose(out);

    /* Cleanup. */
    teardown_env(&env, cfg.num_workers);

    return EXIT_SUCCESS;
}