#ifndef UPE_NAT_H
#define UPE_NAT_H

#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include <rte_mbuf.h>

#define NAT_PORT_MIN 10000
#define NAT_PORT_MAX 60000
#define NAT_MAX_ENTRIES (NAT_PORT_MAX - NAT_PORT_MIN)

void nat_init(uint32_t wan_ip);

/*
 * nat_outbound(): Takes outbound packet buffer, modifies it
 * to look like it came from the router, and recalculates the checksums.
 */
void nat_outbound(struct rte_mbuf *m);

/*
 * nat_inbound(): Takes an inbound packet from the outside.
 * If it belongs to a known NAT session, it rewrites the destination to the internal one.
 * Returns 1 if it was a NAT packet, and 0 if it wasn't.
 */
int nat_inbound(struct rte_mbuf *m);

#endif