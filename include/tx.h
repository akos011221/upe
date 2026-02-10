#ifndef TX_H
#define TX_H

#include <stddef.h>
#include <stdint.h>

#define TX_BATCH_MAX 64

typedef struct {
    int sock_fd;
    int ifindex;
    uint8_t eth_addr[6]; // TX interface's MAC
} tx_ctx_t;

// Initialize a TX context bound to an interface.
// Returns 0 on success, -1 on failure.
int tx_init(tx_ctx_t *ctx, const char *out_iface);

/*
    Send an Ethernet frame.
        Returns 0 on success, -1 on failure.
*/
int tx_send(const tx_ctx_t *ctx, const uint8_t *frame, size_t len);

/*
    Send a batch of Ethernet frames in a single kernel entry.
        Returns number of successfully sent messages, or 0 on error.
*/
int tx_send_batch(const tx_ctx_t *ctx, const uint8_t *const *frames, const size_t *lens, int count);

void tx_close(tx_ctx_t *ctx);

#endif