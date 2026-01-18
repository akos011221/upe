#ifndef UPE_H
#define UPE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "rule_table.h"

typedef struct {
    const char *iface;     // interface name
    const char *pcap_file; // offline pcap file path
    int verbose;           // 0..2
    int duration_sec;      // 0 = run forever

    rule_table_t rt;
} upe_config_t;

#endif