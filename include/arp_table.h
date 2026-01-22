#ifndef ARP_TABLE_H
#define ARP_TABLE_H

#include <stdbool.h>
#include <stdint.h>

/*
    Look up MAC address for an IPv4 address (Host Byte Order).
        Returns true (if found) and writes 6 bytes to out_mac.
*/
bool arp_get_mac(uint32_t ip, uint8_t *out_mac);

#endif