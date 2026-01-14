#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parser.h"
#include "pktbuf.h"
#include "ring.h"
#include "rule_table.h"

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define RESET "\033[0m"

#define TEST_ASSERT(cond)                                                                          \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf(RED "FAIL: %s:%d: " #cond "\n" RESET, __FILE__, __LINE__);                      \
            return -1;                                                                             \
        }                                                                                          \
    } while (0)

#define RUN_TEST(func)                                                                             \
    do {                                                                                           \
        printf("Running %-30s ... ", #func);                                                       \
        if (func() == 0) {                                                                         \
            printf(GREEN "PASS\n" RESET);                                                          \
        } else {                                                                                   \
            printf(RED "FAILED\n" RESET);                                                          \
        }                                                                                          \
    } while (0)

// --- Ring Buffer related tests ---
int test_ring_buffer(void) {
    spsc_ring_t r;

    // Test 1) Initialize with non-power-of-two
    // Reason: The ring buffer uses bitwise AND (index & mask) for wrapping around,
    // as it is much faster than the modulo operation (%). But this only works if the
    // capacity is a power of two.
    TEST_ASSERT(ring_init(&r, 100) == -1);

    // Test 2) Initialize with power-of-two
    TEST_ASSERT(ring_init(&r, 4) == 0);

    int a = 1, b = 2, c = 3, d = 4, e = 5;

    // Test 3) Fill ring to capacity. Checking if producer can fill all
    // available slots.
    TEST_ASSERT(ring_push(&r, &a) == true);
    TEST_ASSERT(ring_push(&r, &b) == true);
    TEST_ASSERT(ring_push(&r, &c) == true);
    TEST_ASSERT(ring_push(&r, &d) == true);

    // Test 4) Overflow check. Ring is full currently, a new item must fail.
    TEST_ASSERT(ring_push(&r, &e) == false);

    // Test 5) FIFO (First-In, First-Out) check. What was pushed first, must be
    // received first.
    int *p = (int *)ring_pop(&r);
    TEST_ASSERT(p == &a);

    // Test 6) Wrap-around. One item was popped => 1 free slot. The 'head'
    // index (internal) is increasing (doesn't reset to 0). The ring must
    // wrap this new write to the beginning of the array.
    TEST_ASSERT(ring_push(&r, &e) == true);
    // Head was 4, Capacity is 4. (mask=capacity-1)
    // 4 & 3 = 0, so 'e' must be at slot 0.
    TEST_ASSERT(r.slots[0] == &e);

    // Test 7) Drain the ring. Verify items come out in correct order.
    // Sequence: Pushed [a,b,c,d] -> Popped [a] -> Pushed [e].
    // Current: b (oldest), c, d, e (newest).
    TEST_ASSERT(ring_pop(&r) == &b);
    TEST_ASSERT(ring_pop(&r) == &c);
    TEST_ASSERT(ring_pop(&r) == &d);
    TEST_ASSERT(ring_pop(&r) == &e);

    // Test 8) Underflow check. When ring is empty, popping must return NULL.
    // This will make the worker thread sleep.
    TEST_ASSERT(ring_pop(&r) == NULL);

    ring_destroy(&r);
    return 0;
}

// --- 2. Rule Table related tests ---
int test_rule_priority(void) {
    rule_table_t rt;
    TEST_ASSERT(rule_table_init(&rt, 10) == 0);

    // Create some rules in random priority order.
    rule_t r1 = {.priority = 100, .rule_id = 1};
    rule_t r2 = {.priority = 10, .rule_id = 2};
    rule_t r3 = {.priority = 66, .rule_id = 3};

    rule_table_add(&rt, &r1);
    rule_table_add(&rt, &r2);
    rule_table_add(&rt, &r3);

    // Verify that rules are sorted by priority.
    // This is very important, because the packet matcher iterates
    // through the array linearly and stops at first match.
    TEST_ASSERT(rt.rules[0].priority == 10);
    TEST_ASSERT(rt.rules[1].priority == 66);
    TEST_ASSERT(rt.rules[2].priority == 100);

    rule_table_destroy(&rt);
    return 0;
}

// --- Packet parser related tests ---
int test_packet_parser(void) {
    uint8_t pkt[128];
    memset(pkt, 0, sizeof(pkt));
    flow_key_t k;

    // Test 1) Packet too short for Ethernet header
    TEST_ASSERT(parse_flow_key(pkt, 12, &k) == -1);

    // Build a valid Ethernet header
    struct eth_hdr {
        uint8_t dst[6];
        uint8_t src[6];
        uint16_t ethertype;
    } __attribute__((packed)) *eth = (struct eth_hdr *)pkt;
    eth->ethertype = htons(0x0800); // IPv4

    // Test 2) Packet too short for IP header
    // Eth (14) + 3 byte
    TEST_ASSERT(parse_flow_key(pkt, 17, &k) == -1);

    // Build a valid IP header
    struct ipv4_hdr {
        uint8_t ver_ihl;
        uint8_t tos;
        uint16_t len;
        uint16_t id;
        uint16_t frag;
        uint8_t ttl;
        uint8_t proto;
        uint16_t csum;
        uint32_t src;
        uint32_t dst;
    } __attribute__((packed)) *ip = (struct ipv4_hdr *)(pkt + 14);
    ip->ver_ihl = 0x45; // Ver 4, IHL 5
    ip->proto = 6;      // TCP

    // Test 3) Packet too short for TCP header
    // Eth (14) + IP (20) + 3 byte
    TEST_ASSERT(parse_flow_key(pkt, 37, &k) == -1);

    // Build a valid TCP header
    pkt[14 + 20 + 12] = 0x50;

    // Test 4) Valid parse
    // Eth (14) + IP (20) + TCP (20)
    TEST_ASSERT(parse_flow_key(pkt, 60, &k) == 0);

    return 0;
}

int main(void) {
    printf("=-> UPE Component Tests <-=\n");
    RUN_TEST(test_ring_buffer);
    RUN_TEST(test_rule_priority);
    RUN_TEST(test_packet_parser);
    return 0;
}