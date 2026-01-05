#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#include "log.h"
#include "parser.h"
#include "rx.h"

#include <arpa/inet.h>
#include <errno.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pcap_t *g_pcap = NULL;

static const char *ipv4_to_str(uint32_t host_ip, char *buf, size_t buflen) {
    struct in_addr addr;
    addr.s_addr = htonl(host_ip);
    return inet_ntop(AF_INET, &addr, buf, (socklen_t)buflen);
}

static void process_packet(const rule_table_t *rt, const uint8_t *pkt, size_t len) {
    flow_key_t k;

    if (parse_flow_key(pkt, len, &k) != 0) {
        return;
    }

    const rule_t *r = rule_table_match(rt, &k);

    if (!r) {
        return;
    }

    flow_action_t a = r->action;
    if (a.type != ACT_DROP && a.type != ACT_FWD) {
        log_msg(LOG_DEBUG, "Unknown action type");
    }

    if (a.type == ACT_DROP) {
        return;
    }

    if (a.type == ACT_FWD) {
        char sbuf[INET_ADDRSTRLEN];
        char dbuf[INET_ADDRSTRLEN];

        log_msg(LOG_DEBUG, "MATCH %s:%u -> %s:%u proto=%u action=FWD out_ifindex=%d",
                ipv4_to_str(k.src_ip, sbuf, sizeof(sbuf)), k.src_port,
                ipv4_to_str(k.dst_ip, dbuf, sizeof(dbuf)), k.dst_port, k.protocol, a.out_ifindex);
    }
}

static void pcap_callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes) {
    const rule_table_t *rt = (const rule_table_t *)user;
    process_packet(rt, bytes, hdr->caplen);
}

int rx_start(const char *iface, const rule_table_t *rt) {
    char errbuf[PCAP_ERRBUF_SIZE];
    g_pcap = pcap_open_live(iface, 65535, 1, 1, errbuf);

    if (!g_pcap) {
        log_msg(LOG_ERROR, "pcap_open_live failed: %s", errbuf);
        return -1;
    }

    log_msg(LOG_INFO, "RX started on %s", iface);

    int rc = pcap_loop(g_pcap, -1, pcap_callback, (u_char *)rt);

    log_msg(LOG_WARN, "pcap_loop exited: %d", rc);
    return 0;
}

void rx_stop(void) {
    if (g_pcap) {
        pcap_breakloop(g_pcap);
    }
}