#ifndef TX_H
#define TX_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    int sock_fd;
    int ifindex;
} tx_ctx_t;

// Initialize a TX context bound to an interface.
// Returns 0 on success, -1 on failure.
int tx_init(tx_ctx_t *ctx, const char *out_iface);

/*
    Send an Ethernet frame.
        Returns 0 on success, -1 on failure.
*/
int tx_send(const tx_ctx_t *ctx, const uint8_t *frame, size_t len);

void tx_close(tx_ctx_t *ctx);

#endif