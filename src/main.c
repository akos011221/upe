#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "rule_table.h"
#include "rx.h"
#include "upe.h"

static volatile sig_atomic_t g_stop = 0;

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
            "Usage: %s --iface <name> [--verbose <0..2>] [--duration <sec>]\n"
            "\n"
            "  --iface     Network interface name (e.g., eth0)\n"
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
    cfg->verbose = 1;
    cfg->duration_sec = 0;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "--iface") == 0) {
            if (i + 1 >= argc) return -1;
            cfg->iface = argv[++i];
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
    if (cfg->iface == NULL) {
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

int main(int argc, char **argv) {
    upe_config_t cfg;

    if (parse_args(argc, argv, &cfg) != 0) {
        usage(argv[0]);
        return 2;
    }

    log_set_level(verbosity_to_level(cfg.verbose));

    if (flow_table_init(&cfg.ft, 4096) != 0) {
        log_msg(LOG_ERROR, "flow_table_init failed");
        return 1;
    }

    log_msg(LOG_INFO, "upe started");
    log_msg(LOG_INFO, "iface=%s, verbose=%d, duration=%d", cfg.iface, cfg.verbose,
            cfg.duration_sec);

    install_signal_handlers();

    install_demo_flows(&cfg.ft);

    log_msg(LOG_INFO, "starting RX");
    rx_start(cfg.iface, &cfg.ft);

    log_msg(LOG_INFO, "upe shutting down");
    return 0;
}