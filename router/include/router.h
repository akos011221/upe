#ifndef ROUTER_H
#define ROUTER_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_mbuf.h>
#include "mac_table.h"
#include "latency.h"

#define NUM_PORTS 2

#define BURST_SIZE 32 /* RX/TX burst size */

/* Memory pool configuration */
#define MBUF_POOL_SIZE 4096
#define MBUF_CACHE_SIZE 256
#define MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE

#define DEFAULT_AGING_TIMEOUT_SEC 30

#define DEFAULT_LINK_WAIT_SEC 5

/* Router configuration */
typedef struct {
    bool dev_mode; /* Use tap vdevs instead of physical NIC */
    bool benchmark_mode;
    uint32_t benchmark_duration_sec;
    uint32_t aging_timeout_sec; /* MAC table aging timeout */
    uint32_t link_wait_sec;
} router_config_t;

/* Per-port TX burst buffer */
typedef struct {
    struct rte_mbuf *mbufs[BURST_SIZE];
    uint16_t count;
} tx_buffer_t;

/* RX lcore context (worker thread data) */
typedef struct {
    mac_table_t mac_table;
    latency_histogram_t latency_hist[NUM_PORTS];
    tx_buffer_t tx_buffers[NUM_PORTS];
    uint64_t packets_forwarded;
    uint64_t bytes_forwarded;
    uint64_t packets_flooded;
    uint64_t packets_dropped;
    uint64_t pool_exhaustion_count;
    double cycles_per_ns;
    volatile bool stop;
} rx_lcore_ctx_t;

/* Global router state */
typedef struct {
    router_config_t config;
    struct rte_mempool *mbuf_pool;
    uint16_t port_ids[NUM_PORTS];
    rx_lcore_ctx_t rx_ctx;
    uint64_t start_tsc;
    uint64_t end_tsc;
} router_state_t;

int rx_lcore_main(void *arg);
void signal_handler(int signum);

#endif /* ROUTER_H */