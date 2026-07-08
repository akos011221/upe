#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mock_dpdk.h"

#include "../src/rx_lcore.c"

uint32_t mock_mbuf_allocated = 0;
uint32_t mock_mbuf_freed = 0;

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define ASSERT(cond, msg)                                                                          \
    do {                                                                                           \
        g_tests_run++;                                                                             \
        if (cond) {                                                                                \
            g_tests_passed++;                                                                      \
        } else {                                                                                   \
            g_tests_failed++;                                                                      \
            fprintf(stderr, "FAIL [%s:%d] %s\n", __FILE__, __LINE__, msg);                         \
        }                                                                                          \
    } while (0)

/* Test data */
static const uint8_t MAC_HOST_A[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x0A};
static const uint8_t MAC_HOST_B[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x0B};
static const uint8_t MAC_BROADCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static void setup_ctx(rx_lcore_ctx_t *ctx) {
    memset(ctx, 0, sizeof(rx_lcore_ctx_t));
    mac_table_init(&ctx->mac_table, 30, 2.0);
    ctx->cycles_per_ns = 2.0;
}

static void test_mac_learning_and_flooding() {
    rx_lcore_ctx_t ctx;
    setup_ctx(&ctx);

    /* Host A (Port 0) sends a packet to Host B (Unknown port) */
    struct rte_mbuf *pkt = mock_build_packet(0, MAC_HOST_A, MAC_HOST_B, 0x0800);

    /* Process the packet */
    forward_mbuf(&ctx, pkt, 0, rdtsc());

    uint16_t learned_port;
    bool found = mac_table_lookup(&ctx.mac_table, MAC_HOST_A, rdtsc(), &learned_port);

    ASSERT(found == true, "MAC Table should have learned Host A's MAC");
    ASSERT(learned_port == 0, "Host A's MAC should be mapped to Port 0");

    /* Because Host B was unknown, it should have flooded to Port 1 */
    ASSERT(ctx.packets_flooded == 1, "Packet to unknown MAC should trigger flood");
    ASSERT(ctx.tx_buffers[1].count == 1, "Packet should be in Port 1's TX queue");
    ASSERT(ctx.tx_buffers[0].count == 0, "Packet shouldn't be in Port 0's TX queue");
}

static void test_unicast_forwarding() {
    rx_lcore_ctx_t ctx;
    setup_ctx(&ctx);

    /* Populate MAC table with Host B on Port 1 */
    mac_table_insert(&ctx.mac_table, MAC_HOST_B, 1, rdtsc());

    /* Host A (Port 0) sends a packet to Host B */
    struct rte_mbuf *pkt = mock_build_packet(0, MAC_HOST_A, MAC_HOST_B, 0x0800);

    forward_mbuf(&ctx, pkt, 0, rdtsc());

    ASSERT(ctx.packets_forwarded == 1, "Packet should be unicast forwarded, not flooded");
    ASSERT(ctx.packets_flooded == 0, "Packet shouldn't be flooded");
    ASSERT(ctx.tx_buffers[1].count == 1, "Packet should be in Port 1's TX queue");
}

static void test_broadcast_flooding() {
    rx_lcore_ctx_t ctx;
    setup_ctx(&ctx);

    /* Host A (Port 0) sends an ARP Broadcast */
    struct rte_mbuf *pkt = mock_build_packet(0, MAC_HOST_A, MAC_BROADCAST, 0x0806);

    forward_mbuf(&ctx, pkt, 0, rdtsc());

    ASSERT(ctx.packets_flooded == 1, "Broadcast packet must be flooded");
    ASSERT(ctx.tx_buffers[1].count == 1, "Broadcast copy should go to Port 1");
}

static void test_hairpin_drop() {
    rx_lcore_ctx_t ctx;
    setup_ctx(&ctx);

    /* Host A is on Port 0 */
    mac_table_insert(&ctx.mac_table, MAC_HOST_A, 0, rdtsc());

    /* Something on Port 0 sends a packet to Host A */
    struct rte_mbuf *pkt = mock_build_packet(0, MAC_HOST_B, MAC_HOST_A, 0x0800);

    forward_mbuf(&ctx, pkt, 0, rdtsc());

    ASSERT(ctx.packets_dropped == 1, "Packet should be dropped if ingress == egress port");
    ASSERT(ctx.tx_buffers[0].count == 0, "Packet shouldn't be queued for transmission");
}

int main() {
    printf("Running Forwarding Tests...\n");
    printf("--------------------------------------------------\n");

    test_mac_learning_and_flooding();
    test_unicast_forwarding();
    test_broadcast_flooding();
    test_hairpin_drop();

    printf("\nResults: %d Passed, %d Failed\n", g_tests_passed, g_tests_failed);

    return g_tests_failed == 0 ? 0 : 1;
}