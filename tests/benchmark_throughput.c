/*
    Benchmark e2e throughput.

    This benchmark measures the maximum processing speed of UPE. It removes the network hardware
    from the picture by creating a __Synthetic NIC__ (main thread) that generates packets in memory
    and pushes them into the ring buffer.

    The __Synthetic NIC__ aka the Producer:
        1) allocates buffer from the pool
        2) fills it with dummy TCP/IP data
        3) pushes int into the ring buffer
        4) repeats this as fast as possible for 10 seconds

    The Worker aka the Consumer:
        1) Pops the packets from the ring
        2) Parses them
        3) Matches them against rule table
        4) Drops them
        5) Frees the buffer back to the pool
*/

#include "arp_table.h"
#include "pktbuf.h"
#include "ring.h"
#include "rule_table.h"
#include "worker.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TEST_DURATION_SEC 10
#define POOL_SIZE 8192
#define RING_SIZE 1024
#define BATCH_SIZE 32

// Dummy definitions (stubs) to satisfy worker.c dependencies
volatile int g_stop = 0;
int tx_send(const tx_ctx_t *ctx, const uint8_t *frame, size_t len) {
    (void)ctx;
    (void)frame;
    (void)len;
    return 0;
}
// --------------------------------------------

// Helper that builds a valid TCP packet.
static void build_dummy_packet(pktbuf_t *b) {
    // Eth (14) + IP (20) + TCP (20) = 54 bytes
    b->len = 54;
    uint8_t *p = b->data;

    // Ethernet
    memset(p, 0, 14);
    p[12] = 0x08; // EtherType part1
    p[13] = 0x00; // EtherType part2

    // IP
    p += 14;
    memset(p, 0, 20);
    p[0] = 0x45; // Ver 4, IHL 5
    p[8] = 32;   // TTL
    p[9] = 6;    // Protocol (TCP)
    // Src: 10.128.0.1
    p[12] = 10;
    p[13] = 128;
    p[14] = 0;
    p[15] = 1;
    // Dst: 10.128.0.2
    p[16] = 10;
    p[17] = 128;
    p[18] = 0;
    p[19] = 2;

    // TCP
    p += 20;
    memset(p, 0, 20);
    p[12] = 0x50; // Data offset 5 words
}

int main(void) {
    printf("=-> UPE e2e Throughput Benchmark <-=\n");

    // 1) Setup
    pktbuf_pool_t pool;
    pktbuf_pool_init(&pool, POOL_SIZE);

    spsc_ring_t ring;
    ring_init(&ring, RING_SIZE);

    rule_table_t rt;
    rule_table_init(&rt, 1024);

    rule_t r = {.priority = 10, .protocol = 6, .action = {.type = ACT_FWD, .out_ifindex = 1}};
    rule_table_add(&rt, &r);

    arp_table_t arpt;
    arp_table_init(&arpt, 1024);

    uint32_t dst_ip = (10U << 24) | (128U << 16) | (0U << 8) | 2U; // 10.128.0.2
    uint8_t dst_mac[6] = {0xaa, 0x00, 0x00, 0x00, 0x00, 0xbb};
    arp_update(&arpt, dst_ip, dst_mac);

    tx_ctx_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.eth_addr[5] = 0xbb;

    // 2) Start a worker
    worker_t w;
    // NULL for TX, as we're only dropping.
    worker_init(&w, 0, &ring, &pool, &rt, &tx, &arpt);
    worker_start(&w);

    printf("Benchmarking for %d seconds...\n", TEST_DURATION_SEC);

    // 3) Run a fake NIC as Producer
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    uint64_t pushed_count = 0;
    time_t start_sec = time(NULL);

    while (time(NULL) - start_sec < TEST_DURATION_SEC) {
        // Push a batch of packets
        for (int i = 0; i < BATCH_SIZE; i++) {
            pktbuf_t *b = pktbuf_alloc(&pool);
            if (!b) {
                // Pool empty, worker has to free some
                break;
            }

            build_dummy_packet(b);

            if (!ring_push(&ring, b)) {
                // Ring is full, free the buffer and back off
                pktbuf_free(&pool, b);
                break;
            }
            pushed_count++;
        }
    }

    // 4) Measure
    clock_gettime(CLOCK_MONOTONIC, &end);
    double seconds = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("------------------------------------------------\n");
    printf("Packets Pushed: %lu\n", pushed_count);
    printf("Time Elapsed:   %.4f s\n", seconds);
    printf("Throughput:     %.2f Mpps (Million Packets/sec)\n", (pushed_count / seconds) / 1e6);
    printf("------------------------------------------------\n");

    // 5) Cleanup (force exit)
    return 0;
}