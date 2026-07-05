#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "mac_table.h"

static int g_tests_run      = 0;
static int g_tests_passed   = 0;
static int g_tests_failed   = 0;

#define ASSERT(cond, msg)
\
    do {
\
        g_tests_run++;
\
        if (cond) {
\
            g_tests_passed++;
\
        } else {
\
            g_tests_failed++;
\
            fprintf(stderr, "FAIL [%s:%d] %s\n",
                    __FILE__, __LINE__, msg);
\
        }
\
    } while (0)

/* Fake TSC to have a simple counter that's deterministic to be able to simulate "n seconds passed" */
#define FAKE_CYCLES_PER_NS 1.0

#define FAKE_AGING_TIMEOUT_SEC 30
#define FAKE_AGING_TIMEOUT_TSC ((uint64_t)(FAKE_AGING_TIMEOUT_SEC) * 1000000000ULL)

/* Build MAC addresses from a single seed byte. */

static void make_unicast_mac(uint8_t mac[MAC_ADDR_LEN], uint8_t seed) {
    /* First byte needs its LSB cleared (to be 0), so it's unicast. */
    mac[0] = seed & 0xFE

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
 *
 * Tests with 200 different MAC addresses.
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
 *
 * This verifies the "update existing entry" branch in mac_table_insert().
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
    ASSERT(found,           "P2: initial insert must be found");
    ASSERT(out_port == 0,   "P2: initial port must be 0");

    /* Moves to port 1 */
    mac_table_insert(&table, mac, 1, tsc2);

    out_port = 0xFF;
    found = mac_table_lookup(&table, mac, tsc2, &out_port);
    ASSERT(found,           "P2: after port update, MAC must still be found");
    ASSERT(out_port == 1,   "P2: after port update, port must be 1");
}
