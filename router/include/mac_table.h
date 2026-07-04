#ifndef MAC_TABLE_H
#define MAC_TABLE_H

#include <stdint.h>
#include <stdbool.h>

#define MAC_ADDR_LEN 6
#define MAC_TABLE_CAPACITY 2048
#define MAC_TABLE_MAX_PROBE 16  /* Maximum linear probe distance before giving up */

typedef struct {
    uint8_t mac[MAC_ADDR_LEN];
    uint16_t port_id;
    uint64_t last_seen_tsc;
    bool occupied;
} mac_entry_t;

typedef struct {
    mac_entry_t entries[MAC_TABLE_CAPACITY];
    uint64_t table_full_count;  /* How many times table was full */
    uint64_t aging_timeout_tsc; /* Timeout in TSC cycles (default 30s) */
} mac_table_t;

/**
 * Initialize MAC table
 * @param table Pointer to table structure
 * @param aging_timeout_sec Aging timeout in seconds
 * @param cycles_per_ns TSC cycles per nanosecond (from calibration)
*/
void mac_table_init(mac_table_t *table, uint32_t aging_timeout_sec,
                    double cycles_per_ns);

/**
 * Insert or update a MAC entry in the table
 * @param table Pointer to table structure
 * @param mac MAC address to insert
 * @param port_id Port ID where the MAC was seen
 * @return true if successful, false if table is full
*/
bool mac_table_insert(mac_table_t *table, const uint8_t mac[MAC_ADDR_LEN],
                      uint16_t port_id, uint64_t current_tsc);

/**
 * Lookup MAC address in table
 * @param table Pointer to table structure
 * @param mac MAC address to lookup
 * @param current_tsc Current TSC value for aging check
 * @param out_port Output for port_id if found
 * @return true if MAC found and not expired, false otherwise
*/
bool mac_table_lookup(mac_table_t *table, const uint8_t mac[MAC_ADDR_LEN],
                      uint64_t current_tsc, uint16_t *out_port);

/**
 * Check if MAC address is unicast (the first octet's LSB is 0)
 * @param mac MAC address to check
 * @return true if unicast
*/
static inline bool mac_is_unicast(const uint8_t mac[MAC_ADDR_LEN]) {
    return (mac[0] & 0x01) == 0;
}

/**
 * Check if MAC address is broadcast (FF:FF:FF:FF:FF:FF)
 * @param mac MAC address to check
 * @return true if broadcast
*/
static inline bool mac_is_broadcast(const uint8_t mac[MAC_ADDR_LEN]) {
    return mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF &&
           mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF;
}

#endif /* MAC_TABLE_H */
