#ifndef RX_H
#define RX_H

#include <stddef.h>
#include <stdint.h>

#include "rule_table.h"

/*
    Start packet capture on an interface.
    Blocks until upe is stopped by signal.
*/
int rx_start(const char *iface, const rule_table_t *rt);

/*
    Stop packet capture.
*/
void rx_stop(void);

#endif