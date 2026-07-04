#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>

/* DPDK headers */
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_lcore.h>
#include <rte_launch.h>
#include <rte_errno.h>

/* UPE engine headers */
#include "log.h"
#include "latency.h"

#include "router.h"
#include "mac_table.h"


static router_state_t g_router;

void signal_handler(int signum) {
    (void)signum;
    log_msg(LOG_INFO, "Signal received, stopping...");
    g_router.rx_ctx.stop = true;
}

static void print_usage(const char *prog_name) {
    printf("Usage: %s [EAL options] -- [application options]\n", prog_name);
    printf("\nApplication options:\n");
    printf("  --dev-mode              Use tap vdevs instead of physical NIC\n");
    printf("  --benchmark             Run in benchmark mode\n");
    printf("  --benchmark-duration N  Benchmark duration in seconds (default: 10)\n");
    printf("  --aging-timeout N       MAC table aging timeout in seconds (default: 30)\n");
    printf("  --link-wait N           Link wait timeout in seconds (default: 5)\n");
    printf("  --help                  Show this help message\n");
    printf("\nExample:\n");
    printf("  %s -c 0x3 -n 4 -- --dev-mode\n", prog_name);
    printf("  %s -c 0x3 -n 4 -- --benchmark --benchmark-duration 60\n", prog_name);
}

static int parse_app_args(int argc, char **argv, router_config_t *config) {
    /* Set defaults */
    config->dev_mode = false;
    config->benchmark_mode = false;
    config->benchmark_duration_sec = 10;
    config->aging_timeout_sec = DEFAULT_AGING_TIMEOUT_SEC;
    config->link_wait_sec = DEFAULT_LINK_WAIT_SEC;

    static struct option long_options[] = {
        {"dev-mode", no_argument, NULL, 'd'},
        {"benchmark", no_argument, NULL, 'b'},
        {"benchmark-duration", required_argument, NULL, 'D'},
        {"aging-timeout", required_argument, NULL, 'a'},
        {"link-wait", required_argument, NULL, 'l'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
        switch (opt) {
            case 'd':
                config->dev_mode = true;
                break;
            case 'b':
                config->benchmark_mode = true;
                break;
            case 'D':
                config->benchmark_duration_sec = (uint32_t)atoi(optarg);
                if (config->benchmark_duration_sec < 1 ||
                    config->benchmark_duration_sec > 3600) {
                        log_msg(LOG_ERROR, "Benchmark duration must be 1-3600 seconds");
                        return -1;
                    }
                    break;
            case 'a':
                    config->aging_timeout_sec = (uint32_t)atoi(optarg);
                    if (config->aging_timeout_sec < 1) {
                        log_msg(LOG_ERROR, "Aging timeout must be >= 1 second");
                        return -1;
                    }
                    break;
            case 'l':
                    config->link_wait_sec = (uint32_t)atoi(optarg);
                    if (config->link_wait_sec < 1 || config->link_wait_sec > 60) {
                        log_msg(LOG_ERROR, "Link wait must be 1-60 seconds");
                        return -1;
                    }
                    break;
            case 'h':
                    print_usage(argv[0]);
                    exit(0);
            default:
                    print_usage(argv[0]);
                    return -1;
        }
    }

    return 0;
}

static int port_init(uint16_t port_id, struct rte_mempool *mbuf_pool,
                     uint32_t link_wait_sec) {
    struct rte_eth_conf port_conf = {0};
    const uint16_t rx_rings = 1;
    const uint16_t tx_rings = 1;
    uint16_t nb_rxd = 128; /* RX descriptors */
    uint16_t nb_txd = 512; /* TX descriptors */
    int ret;
    struct rte_eth_dev_info dev_info;

    /* Get device info */
    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0) {
        log_msg(LOG_ERROR, "Failed to get device info for port %u: %s",
                port_id, rte_strerror(-ret));
        return ret;
    }

    /* Configure the device */
    ret = rte_eth_dev_configure(port_id, rx_rings, tx_rings, &port_conf);
    if (ret != 0) {
        log_msg(LOG_ERROR, "Failed to configure port %u: %s",
                port_id, rte_strerror(-ret));
        return ret;
    }

    /* Adjust descriptor counts if needed */
    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
    if (ret != 0) {
        log_msg(LOG_ERROR, "Failed to adjust descriptor counts for port %u: %s",
                port_id, rte_strerror(-ret));
        return ret;
    }

    /* Setup RX queue */
    ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
                                 rte_eth_dev_socket_id(port_id),
                                 NULL, mbuf_pool);
    if (ret < 0) {
        log_msg(LOG_ERROR, "Failed to setup RX queue for port %u: %s",
                port_id, rte_strerror(-ret));
        return ret;
    }

    /* Setup TX queue */
    ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd,
                                 rte_eth_dev_socket_id(port_id),
                                 NULL);
    if (ret < 0) {
        log_msg(LOG_ERROR, "Failed to setup TX queue for port %u: %s",
                port_id, rte_strerror(-ret));
        return ret;
    }

    /* Start the device */
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        log_msg(LOG_ERROR, "Failed to start port %u: %s",
                port_id, rte_strerror(-ret));
        return ret;
    }

    /* Enable promiscuous mode */
    ret = rte_eth_promiscuous_enable(port_id);
    if (ret != 0) {
        log_msg(LOG_ERROR, "Failed to enable promiscuous mode on port %u: %s",
                port_id, rte_strerror(-ret));
        return ret;
    }

    /* Wait for link up */
    struct rte_eth_link link;
    uint32_t wait_count = 0;
    const uint32_t max_wait = link_wait_sec * 10;

    do {
        ret = rte_eth_link_get_nowait(port_id, &link);
        if (ret < 0) {
            log_msg(LOG_ERROR, "Failed to get link status for port %u: %s",
                    port_id, rte_strerror(-ret));
            return ret;
        }

        if (link.link_status == RTE_ETH_LINK_UP) {
            log_msg(LOG_INFO, "Port %u: Link up. Speed %u Mbps, %s",
                    port_id, link.link_speed,
                    (link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ? 
                    "full-duplex": "half-duplex");
            return 0;
        }

        rte_delay_ms(100);
        wait_count++;
    } while (wait_count < max_wait);

    /* Link still down after timeout */
    log_msg(LOG_WARN, "Port %u: Link down after %u second timeout,
            continuing anyway", port_id, link_wait_sec);
    return 0;
}

static void print_stats(const rx_lcore_ctx_t *ctx, double cycles_per_ns) {
    /* Print latency histogram for each port */
    for (uint16_t port = 0; port < NUM_PORTS; port++) {
        const latency_histogram_t *hist = &ctx->latency_hist[port];

        if (hist->total_count == 0) {
            continue; /* No packets on the port yet */
        }

        uint64_t p50 = latency_percentile(hist, 0.50);
        uint64_t p99 = latency_percentile(hist, 0.99);
        uint64_t p999 = latency_percentile(hist, 0.999);

        log_msg(LOG_INFO,
                "Port %u: pkts=%lu, p50=%lu ns, p99=%lu ns, p999=%lu ns, "
                 "min=%lu ns, max=%lu ns",
                 port, hist->total_count, p50, p99, p999,
                 hist->min_ns, hist->max_ns);
    }

    log_msg(LOG_INFO,
            "Forwarding: pkts=%lu, bytes=%lu, flooded=%lu, dropped=%lu, "
            "pool_exhausted=%lu, mac_table_full=%lu",
            ctx->packets_forwarded, ctx->bytes_forwarded,
            ctx->packets_flooded, ctx->packets_dropped,
            ctx->pool_exhaustion_count, ctx->mac_table.table_full_count);
}

int main(int argc, char **argv) {
    int ret;
    unsigned int lcore_id;

    log_set_level(LOG_INFO);

    memset(&g_router, 0, sizeof(g_router));

    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        log_msg(LOG_ERROR, "EAL initialization failed: %s",
                rte_strerror(rte_errno));
        return EXIT_FAILURE;
    }

    /* Advance argc/argv past EAL arguments */
    argc -= ret;
    argv += ret;

    if (parse_app_args(argc, argv, &g_router.config) < 0) {
        rte_eal_cleanup();
        return EXIT_FAILURE;
    }

    unsigned int nb_lcores = rte_lcore_count();
    if (nb_lcores < 2) {
        log_msg(LOG_ERROR, "At least 2 lcores are required (main + 1 worker), got %u",
                nb_lcores);
        rte_eal_cleanup();
        return EXIT_FAILURE;
    }

    log_msg(LOG_INFO, "Using %u lcores", nb_lcores);

    double cycles_per_ns = latency_calibrate_tsc();
    log_msg(LOG_INFO, "TSC calibration: %.2f cycles/ns", cycles_per_ns);
    g_router.rx_ctx.cycles_per_ns = cycles_per_ns;

    g_router.mbuf_pool = rte_pktmbuf_pool_create(
        "mbuf_pool",
        MBUF_POOL_SIZE,
        MBUF_CACHE_SIZE,
        0,
        MBUF_DATA_SIZE,
        rte_socket_id()
    );

    if (g_router.mbuf_pool == NULL) {
        log_msg(LOG_ERROR, "Failed to create mbuf pool: %s",
                rte_strerror(rte_errno));
        rte_eal_cleanup();
        return EXIT_FAILURE;
    }

    log_msg(LOG_INFO, "Created mbuf pool with %u mbufs", MBUF_POOL_SIZE);

    uint16_t nb_ports;
    if (g_router.config.dev_mode) {
        log_msg(LOG_INFO, "Creating tap vdevs for development mode");

        ret = rte_eal_hotplug_add("vdev", "net_tap0", "");
        if (ret < 0) {
            log_msg(LOG_ERROR, "Failed to create net_tap0: %s",
                    rte_strerror(-ret));
            rte_eal_cleanup();
            return EXIT_FAILURE;
        }

        ret = rte_eal_hotplug_add("vdev", "net_tap1", "");
        if (ret < 0) {
            log_msg(LOG_ERROR, "Failed to create net_tap1: %s",
                    rte_strerror(-ret));
            rte_eal_cleanup();
            return EXIT_FAILURE;
        }

        nb_ports = rte_eth_dev_count_avail();
        log_msg(LOG_INFO, "Created %u tap vdev ports", nb_ports);
    } else {
        nb_ports = rte_eth_dev_count_avail();
        log_msg(LOG_INFO, "Found %u physical ports", nb_ports);
    }

    if (nb_ports != NUM_PORTS) {
        log_msg(LOG_ERROR, "Expected %u ports, found %u", NUM_PORTS, nb_ports);
        rte_eal_cleanup();
        return EXIT_FAILURE;
    }

    uint16_t port_id;
    RTE_ETH_FOREACH_DEV(port_id) {
        if (port_id >= NUM_PORTS) {
            break;
        }

        g_router.port_ids[port_id] = port_id;

        ret = port_init(port_id, g_router.mbuf_pool,
                        g_router.config.link_wait_sec);
        if (ret < 0) {
            log_msg(LOG_ERROR, "Failed to initialize port %u",
                    port_id);
            rte_eal_cleanup();
            return EXIT_FAILURE;
        }

        log_msg(LOG_INFO, "Initialized port %u", port_id);
    }

    mac_table_init(&g_router.rx_ctx.mac_table,
                   g_router.config.aging_timeout_sec,
                   cycles_per_ns);
    
    for (uint16_t i = 0; i < NUM_PORTS; i++) {
        latency_histogram_init(&g_router.rx_ctx.latency_hist[i]);
        g_router.rx_ctx.tx_buffers[i].count = 0;
    }

    g_router.rx_ctx.stop = false;

    log_msg(LOG_INFO, "Initialized RX context");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Get the first worker lcore */
    lcore_id = rte_get_next_lcore(-1, 1, 0);
    if (lcore_id == RTE_MAX_LCORE) {
        log_msg(LOG_ERROR, "No worker lcore available");
        rte_eal_cleanup();
        return EXIT_FAILURE;
    }

    log_msg(LOG_INFO, "Launching RX worker on lcore %u", lcore_id);

    /* Launch RX worker on dedicated lcore */
    ret = rte_eal_remote_launch(rx_lcore_main, &g_router.rx_ctx,
                                lcore_id);
    if (ret < 0) {
        log_msg(LOG_ERROR, "Failed to launch RX worker: %s",
                rte_strerror(-ret));
        rte_eal_cleanup();
        return EXIT_FAILURE;
    }

    /* Recording start time for benchmark mode */
    if (g_router.config.benchmark_mode) {
        g_router.start_tsc = rdtsc();
        log_msg(LOG_INFO, "Starting benchmark for %u seconds",
                g_router.config.benchmark_duration_sec);
    }

    /* Print stats every second */
    while (!g_router.rx_ctx.stop) {
        sleep(1);

        /* In benchmark mode, check if duration elapsed */
        if (g_router.config.benchmark_mode) {
            uint64_t current_tsc = rdtsc();
            uint64_t elapsed_tsc = current_tsc - g_router.start_tsc;
            double elapsed_sec = (double)elapsed_tsc /
                                 (cycles_per_ns * 1000000000.0);

            if (elapsed_sec >= g_router.config.benchmark_duration_sec) {
                g_router.end_tsc = current_tsc;
                g_router.rx_ctx.stop = true;
                break;
            }
        } else {
            /* Normal mode */
            print_stats(&g_router.rx_ctx, cycles_per_ns);
        }
    }

    log_msg(LOG_INFO, "Stopping router...");

    /* Wait for RX worker to finish */
    ret = rte_eal_wait_lcore(lcore_id);
    if (ret < 0) {
        log_msg(LOG_ERROR, "RX worker returned error: %d", ret);
    }

    /* Print final stats */
    if (g_router.config.benchmark_mode) {
        double duration_sec = (double)(g_router.end_tsc - g_router.start_tsc) /
                                (cycles_per_ns * 1000000000.0);
        double pps = (double)g_router.rx_ctx.packets_forwarded / duration_sec;
        double gbps = (double)g_router.rx_ctx.bytes_forwarded * 8.0 /
                        (duration_sec * 1000000000.0);
        
        uint64_t p50 = 0, p99 = 0, p999 = 0, min_ns = 0, max_ns = 0;
        for (uint16_t port = 0; port < NUM_PORTS; port++) {
            const latency_histogram_t * hist =
                &g_router.rx_ctx.latency_hist[port];
            if (hist->total_count > 0) {
                p50 = latency_percentile(hist, 0.50);
                p99 = latency_percentile(hist, 0.99);
                p999 = latency_percentile(hist, 0.999);
                min_ns = hist->min_ns;
                max_ns = hist->max_ns;
                break; /* Use first port with data */
            }
        }

            /* Print JSON to stdout */
        printf("{\n");
        printf("  \"duration_sec\": %.3f,\n", duration_sec);
        printf("  \"results\": {\n");
        printf("    \"throughput_pps\": %.0f,\n", pps);
        printf("    \"throughput_gbps\": %.3f\n", gbps);
        printf("  },\n");
        printf("  \"latency\": {\n");
        printf("    \"p50_ns\": %lu,\n", p50);
        printf("    \"p99_ns\": %lu,\n", p99);
        printf("    \"p999_ns\": %lu,\n", p999);
        printf("    \"min_ns\": %lu,\n", min_ns);
        printf("    \"max_ns\": %lu\n", max_ns);
        printf("  }\n");
        printf("}\n");

        if (pps < 1000000.0) {
            log_msg(LOG_WARN, "Throughput %.0f pps is below 1 Mpps floor,
                    need investigation...", pps);
        }
    } else {
        /* Normal mode: just print final stats */
        log_msg(LOG_INFO, "Final statistics:");
        print_stats(&g_router.rx_ctx, cycles_per_ns);
    }

    /* Stop and close ports */
    RTE_ETH_FOREACH_DEV(port_id) {
        if (port_id >= NUM_PORTS) {
            break;
        }

        log_msg(LOG_INFO, "Stopping port %u", port_id);
        ret = rte_eth_dev_stop(port_id);
        if (ret != 0) {
            log_msg(LOG_ERROR, "Failed to stop port %u: %s",
                    port_id, rte_strerror(-ret));
        }

        rte_eth_dev_close(port_id);
    }

    rte_eal_cleanup();

    log_msg(LOG_INFO, "Router stopped cleanly");
    return EXIT_SUCCESS;
}