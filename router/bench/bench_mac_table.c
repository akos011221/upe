#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mac_table.h"
#include "router.h"

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

/* Fake TSC to have a simple counter that's deterministic to be able to simulate "n seconds passed"
 */
#define FAKE_CYCLES_PER_NS 1.0

#define FAKE_AGING_TIMEOUT_SEC 30
#define FAKE_AGING_TIMEOUT_TSC ((uint64_t)(FAKE_AGING_TIMEOUT_SEC) * 1000000000ULL)

/* Build MAC addresses from a single seed byte. */

static void make_unicast_mac(uint8_t mac[MAC_ADDR_LEN], uint8_t seed) {
    /* First byte needs its LSB cleared (to be 0), so it's unicast. */
    mac[0] = seed & 0xFE;
    for (int i = 1; i < MAC_ADDR_LEN; i++)
        mac[i] = seed;
}

static void make_multicast_mac(uint8_t mac[MAC_ADDR_LEN], uint8_t seed) {
    /* First byte needs its LSB set (to be 1), so it's multicast. */
    mac[0] = seed | 0x01;

    for (int i = 1; i < MAC_ADDR_LEN; i++)
        mac[i] = seed;
}

static void make_broadcast_mac(uint8_t mac[MAC_ADDR_LEN]) {
    memset(mac, 0xFF, MAC_ADDR_LEN);
}

/* -----------------------------------------------------------------------
 * Property 1: Insert+Lookup round-trip
 *
 * For any unicast MAC M inserted at TSC T on port P,
 * mac_table_lookup(M, T) must return true and out_port == P.
 * -----------------------------------------------------------------------
 */
static void test_insert_lookup_roundtrip(void) {
    mac_table_t table;
    mac_table_init(&table, FAKE_AGING_TIMEOUT_SEC, FAKE_CYCLES_PER_NS);

    for (int seed = 0; seed < 200; seed++) {
        uint8_t mac[MAC_ADDR_LEN];
        /* Multiply by 2 (left shift) so every unique seed maps to a unique even byte.
         * If 'seed' was passed directly:
         *  seed=0 -> 0x00
         *  seed=1 -> 0x00 (it'd be duplicated).
         * seed*2 gives: 0, 2, 4 ... 254, always unique unicast. **/
        make_unicast_mac(mac, (uint8_t)(seed * 2));

        uint16_t insert_port = (uint16_t)(seed % NUM_PORTS);
        uint64_t tsc = (uint64_t)(seed + 1) * 1000;

        bool ok = mac_table_insert(&table, mac, insert_port, tsc);
        ASSERT(ok, "P1: insert should succeed for fresh table");

        uint16_t out_port = 0xFF; /* set to some garbage initially */
        bool found = mac_table_lookup(&table, mac, tsc, &out_port);
        ASSERT(found, "P1: lookup should find just inserted MAC");
        ASSERT(out_port == insert_port, "P1: lookup should return correct port");
    }
}

/* -----------------------------------------------------------------------
 * Property 2: Port update when MAC goes to an other port
 *
 * If MAC M is first seen on port 0, then later seen on port 1,
 * a lookup after the second insert must return port 1.
 * -----------------------------------------------------------------------
 */
static void test_port_update(void) {
    mac_table_t table;
    mac_table_init(&table, FAKE_AGING_TIMEOUT_SEC, FAKE_CYCLES_PER_NS);

    uint8_t mac[MAC_ADDR_LEN];
    make_unicast_mac(mac, 0xAA);

    uint64_t tsc1 = 1000;
    uint64_t tsc2 = 2000;

    /* First seen on port 0 */
    mac_table_insert(&table, mac, 0, tsc1);

    uint16_t out_port = 0xFF;
    bool found = mac_table_lookup(&table, mac, tsc1, &out_port);
    ASSERT(found, "P2: initial insert must be found");
    ASSERT(out_port == 0, "P2: initial port must be 0");

    /* Moves to port 1 */
    mac_table_insert(&table, mac, 1, tsc2);

    out_port = 0xFF;
    found = mac_table_lookup(&table, mac, tsc2, &out_port);
    ASSERT(found, "P2: after port update, MAC must still be found");
    ASSERT(out_port == 1, "P2: after port update, port must be 1");
}

/* -----------------------------------------------------------------------
 * Property 3: Aging Timeout
 *
 * If a MAC is inserted at TSC T, a lookup at T + FAKE_AGING_TIMEOUT_TSC + 1
 * must return false (expired).
 * -----------------------------------------------------------------------
 */
static void test_aging_timeout(void) {
    mac_table_t table;
    mac_table_init(&table, FAKE_AGING_TIMEOUT_SEC, FAKE_CYCLES_PER_NS);

    uint8_t mac[MAC_ADDR_LEN];
    make_unicast_mac(mac, 0xBB);
    uint16_t port = 1;
    uint64_t tsc_insert = 1000;

    mac_table_insert(&table, mac, port, tsc_insert);

    uint16_t out_port = 0xFF;
    uint64_t tsc_exact = tsc_insert + FAKE_AGING_TIMEOUT_TSC;
    bool found_exact = mac_table_lookup(&table, mac, tsc_exact, &out_port);
    ASSERT(found_exact, "P3: MAC should still be valid exactly at timeout boundary");

    uint64_t tsc_expired = tsc_insert + FAKE_AGING_TIMEOUT_TSC + 1;
    bool found_expired = mac_table_lookup(&table, mac, tsc_expired, &out_port);
    ASSERT(!found_expired, "P3: MAC must be treated as expired after timeout window");
}

/* -----------------------------------------------------------------------
 * Property 4: Entry Refreshing
 *
 * Re-inserting or looking up and existing MAC should refresh its
 * last_seen_tsc, preventing it from aging out early.
 * -----------------------------------------------------------------------
 */
static void test_entry_refresh(void) {
    mac_table_t table;
    mac_table_init(&table, FAKE_AGING_TIMEOUT_SEC, FAKE_CYCLES_PER_NS);

    uint8_t mac[MAC_ADDR_LEN];
    make_unicast_mac(mac, 0xCC);
    uint16_t port = 0;

    uint64_t tsc1 = 1000;
    mac_table_insert(&table, mac, port, tsc1);

    /* Advance halfway thru aging and refresh */
    uint64_t tsc2 = tsc1 + (FAKE_AGING_TIMEOUT_TSC / 2);
    mac_table_insert(&table, mac, port, tsc2);

    /* It should survive past the original timeout window */
    uint64_t tsc3 = tsc1 + FAKE_AGING_TIMEOUT_TSC + 100;
    uint16_t out_port = 0xFF;
    bool found = mac_table_lookup(&table, mac, tsc3, &out_port);

    ASSERT(found, "P4: Refreshed MAC should not age out relative to original timestamp");
    ASSERT(out_port == port, "P4: Port should remain intact after refresh");
}

/* -----------------------------------------------------------------------
 * Property 5: Multicast/Broadcast Source Ignored
 *
 * Non-unicast source MAC addresses must never be learned.
 * -----------------------------------------------------------------------
 */
static void test_ignore_non_unicast_sources(void) {
    uint8_t mc_mac[MAC_ADDR_LEN];
    uint8_t bc_mac[MAC_ADDR_LEN];

    make_multicast_mac(mc_mac, 0xDD);
    make_broadcast_mac(bc_mac);

    /* rx_lcore match uses mac_is_unicast() when inserting into the table */
    ASSERT(!mac_is_unicast(mc_mac), "P5: Multicast MAC must not be classified as unicast");
    ASSERT(!mac_is_unicast(bc_mac), "P5: Broadcast MAC must not be classified as unicast");
}

int main(void) {
    printf("Running MAC Table Property-Based Correctness Tests...\n");
    printf("--------------------------------------------------\n");

    test_insert_lookup_roundtrip();
    test_port_update();
    test_aging_timeout();
    test_entry_refresh();
    test_ignore_non_unicast_sources();

    printf("\nTest Execution Summary:\n");
    printf("  Total Assertions Run: %d\n", g_tests_run);
    printf("  Passed:               %d\n", g_tests_passed);
    printf("  Failed:               %d\n", g_tests_failed);

    return (g_tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
