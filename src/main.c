#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "pktbuf.h"
#include "ring.h"
#include "rule_table.h"
#include "rx.h"
#include "tx.h"
#include "upe.h"
#include "worker.h"

volatile sig_atomic_t g_stop = 0;

static void handle_signal(int sig) {
    (void)sig;
    g_stop = 1;
    rx_stop();
}

static void install_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;

    sa.sa_flags = SA_RESTART;

    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) != 0) {
        log_msg(LOG_ERROR, "sigaction(sigint) failed: %s", strerror(errno));
        exit(1);
    }
    if (sigaction(SIGTERM, &sa, NULL) != 0) {
        log_msg(LOG_ERROR, "sigaction(sigterm) failed: %s", strerror(errno));
        exit(1);
    }
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [--iface <name> | --pcap <file>] [--verbose <0..2>] [--duration <sec>]\n"
            "\n"
            "  --iface     Network interface name (e.g., eth0)\n"
            "  --pcap      PCAP file to read from (offline mode)\n"
            "  --verbose   0=warn+error, 1=info (default), 2=debug\n"
            "  --duration  Run time in seconds (0 = forever, default 0)\n",
            prog);
}

static int parse_int(const char *s, int *out) {
    errno = 0;
    char *end = NULL;
    long v = strtol(s, &end, 10);

    if (errno != 0) return -1;
    if (end == s || *end != '\0') return -1;
    if (v < -2147483648L || v > 2147483647L) return -1;

    *out = (int)v;
    return 0;
}

static int parse_args(int argc, char **argv, upe_config_t *cfg) {
    cfg->iface = NULL;
    cfg->pcap_file = NULL;
    cfg->verbose = 1;
    cfg->duration_sec = 0;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "--iface") == 0) {
            if (i + 1 >= argc) return -1;
            cfg->iface = argv[++i];
        } else if (strcmp(arg, "--pcap") == 0) {
            if (i + 1 >= argc) return -1;
            cfg->pcap_file = argv[++i];
        } else if (strcmp(arg, "--verbose") == 0) {
            if (i + 1 >= argc) return -1;
            int v = 0;
            if (parse_int(argv[++i], &v) != 0) return -1;
            if (v < 0 || v > 2) return -1;
            cfg->verbose = v;
        } else if (strcmp(arg, "--duration") == 0) {
            if (i + 1 >= argc) return -1;
            int d = 0;
            if (parse_int(argv[++i], &d) != 0) return -1;
            if (d < 0) return -1;
            cfg->duration_sec = d;
        } else if (strcmp(arg, "--help") == 0) {
            usage(argv[0]);
            exit(0);
        } else {
            return -1;
        }
    }
    if (cfg->iface == NULL && cfg->pcap_file == NULL) {
        return -1;
    }
    return 0;
}

static log_level_t verbosity_to_level(int verbose) {
    // verbose: 0..2
    // level: WARN/INFO/DEBUG
    if (verbose <= 0) return LOG_WARN;
    if (verbose == 1) return LOG_INFO;
    return LOG_DEBUG;
}

static void install_demo_flows(rule_table_t *rt) {
    /*
        Seed the flow table with some demo flows.
    */

    // Drop TCP 22 with the highest priority
    rule_t r1;
    memset(&r1, 0, sizeof(r1));
    r1.priority = 10;
    r1.protocol = 6;
    r1.dst_port = 22;
    r1.action.type = ACT_DROP;
    r1.action.out_ifindex = 0;
    rule_table_add(rt, &r1);

    // Fwd every TCP from 10.0.0.0/8
    rule_t r2;
    memset(&r2, 0, sizeof(r2));
    r2.priority = 100;
    r2.protocol = 6;
    r2.src_ip = (10u << 24) | (0u << 16) | (0u << 8) | 0u; // 10.0.0.0 in host order
    uint32_t src_mask;
    ipv4_mask_from_prefix(8, &src_mask);
    r2.src_mask = src_mask;
    r2.action.type = ACT_FWD;
    r2.action.out_ifindex = 3;
    rule_table_add(rt, &r2);

    // Implicit deny (drop)
    rule_t r3;
    memset(&r3, 0, sizeof(r3));
    r3.priority = 10000;
    r3.action.type = ACT_DROP;
    rule_table_add(rt, &r3);
}

typedef struct {
    worker_t *workers;
    int num_workers;
    const rule_table_t *rt;
} stats_ctx_t;

static void *stats_thread_func(void *arg) {
    stats_ctx_t *ctx = (stats_ctx_t *)arg;

    while (!g_stop) {
        sleep(1); // Stats thread wakes up every second

        printf("\033[2J\033[H");
        printf("=== UPE Statistics ===\n");
        printf("%-6s %-8s %-10s %-15s %-15s\n", "RuleID", "Priority", "Action", "Packets", "Bytes");
        printf("-------------------------------------------------------------\n");

        uint64_t total_pkts = 0;
        uint64_t total_bytes = 0;

        // Iterate over rules, ordered by priority
        for (size_t i = 0; i < ctx->rt->count; i++) {
            const rule_t *r = &ctx->rt->rules[i];
            uint32_t rid = r->rule_id;

            uint64_t p_sum = 0;
            uint64_t b_sum = 0;

            // Aggregate stats from all workers
            for (int w = 0; w < ctx->num_workers; w++) {
                if (ctx->workers[w].rule_stats) {
                    p_sum += ctx->workers[w].rule_stats[rid].packets;
                    b_sum += ctx->workers[w].rule_stats[rid].bytes;
                }
            }

            if (p_sum > 0) {
                printf("%-6u %-8u %-10s %-15lu %-15lu\n", rid, r->priority,
                       (r->action.type == ACT_DROP) ? "DROP" : "FWD", p_sum, b_sum);

                total_pkts += p_sum;
                total_bytes += b_sum;
            }
        }
        printf("-------------------------------------------------------------\n");
        printf("TOTAL: %lu packets, %lu bytes\n", total_pkts, total_bytes);
    }
    return NULL;
}

int main(int argc, char **argv) {
    upe_config_t cfg;

    if (parse_args(argc, argv, &cfg) != 0) {
        usage(argv[0]);
        return 2;
    }

    log_set_level(verbosity_to_level(cfg.verbose));
    install_signal_handlers();

    const int WORKERS_NUM = 2;
    const size_t RING_CAPACITY = 1024;
    const size_t POOL_CAPACITY = 4096;

    // I. Init packet pool.
    pktbuf_pool_t pool;
    if (pktbuf_pool_init(&pool, POOL_CAPACITY) != 0) {
        log_msg(LOG_ERROR, "pktbuf_pool_init failed");
        return 1;
    }

    // II. Init rings; one per worker.
    spsc_ring_t *rings = calloc((size_t)WORKERS_NUM, sizeof(spsc_ring_t));
    for (int i = 0; i < WORKERS_NUM; i++) {
        if (ring_init(&rings[i], RING_CAPACITY) != 0) {
            log_msg(LOG_ERROR, "ring_init failed");
            return 1;
        }
    }

    // III. Init TX context
    tx_ctx_t tx;
    if (tx_init(&tx, cfg.iface ? cfg.iface : "lo") != 0) {
        log_msg(LOG_ERROR, "tx_init failed");
        return 1;
    }

    // IV. Init rule table, add some demo rules
    rule_table_t rt;
    rule_table_init(&rt, 1024);
    install_demo_flows(&rt);

    // V. Start workers
    worker_t *workers = calloc((size_t)WORKERS_NUM, sizeof(worker_t));
    for (int i = 0; i < WORKERS_NUM; i++) {
        worker_init(&workers[i], i, &rings[i], &pool, &rt, &tx);

        if (worker_start(&workers[i]) != 0) {
            log_msg(LOG_ERROR, "worker_start(%d) failed", i);
            return 1;
        }
    }

    // VI. Start RX (blocking)
    rx_ctx_t rx;
    rx.iface = cfg.iface;
    rx.pcap_file = cfg.pcap_file;
    rx.pool = &pool;
    rx.rings = rings;
    rx.ring_count = WORKERS_NUM;

    // Start stats thread
    pthread_t stats_th;
    stats_ctx_t stats_ctx = {.workers = workers, .num_workers = WORKERS_NUM, .rt = &rt};
    pthread_create(&stats_th, NULL, stats_thread_func, &stats_ctx);

    rx_start(&rx);

    // VII. RX returned => stop workers and join
    g_stop = 1;

    // Join stats thread
    pthread_join(stats_th, NULL);

    for (int i = 0; i < WORKERS_NUM; i++) {
        worker_join(&workers[i]);
    }

    // VIII. Cleanup
    tx_close(&tx);
    for (int i = 0; i < WORKERS_NUM; i++) {
        ring_destroy(&rings[i]);
    }
    free(rings);

    pktbuf_pool_destroy(&pool);
    rule_table_destroy(&rt);
    for (int i = 0; i < WORKERS_NUM; i++) {
        worker_destroy(&workers[i]);
    }
    free(workers);

    return 0;
}