#ifndef CTRL_PLANE_H
#define CTRL_PLANE_H

#include "router.h"

#define UPE_IPC_SOCKET "/var/run/upe/router.sock"

int ctrl_plane_start(rx_lcore_ctx_t *ctx, struct rte_mempool *pool);

#endif