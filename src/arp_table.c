#include "arp_table.h"
#include <string.h>

bool arp_get_mac(uint32_t ip, uint8_t *out_mac) {
    if (ip == 0xC0A8014D) {
        uint8_t mac[] = {0x1c, 0x91, 0x80, 0xdf, 0x6c, 0x91};
        memcpy(out_mac, mac, 6);
        return true;
    }

    if (ip == 0xC0A80101) {
        uint8_t mac[] = {0x64, 0x66, 0x24, 0x0d, 0xa2, 0x8d};
        memcpy(out_mac, mac, 6);
        return true;
    }

    return false;
}