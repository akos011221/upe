#include "rule_table.h"
#include <netinet/in.h>
#include <sys/socket.h>
#define _POSIX_C_SOURCE 200809L

#include "rule_config.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

#define MAX_LINE 512

static char *strip(char *s) {
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }

    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)*(end - 1))) {
        end--;
    }

    *end = '\0';
    return s;
}

/*
    Parse "addr/prefix" into ip_addr_t + mask.
        Returns 0 on success, -1 on error.
*/
static int parse_ip_prefix(const char *str, uint8_t *ip_ver, ip_addr_t *ip, ip_addr_t *mask) {
    char buf[INET6_ADDRSTRLEN + 4];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    uint8_t prefix_len;

    if (slash) {
        *slash = '\0';
        errno = 0;
        char *end = NULL;
        long pl = strtol(slash + 1, &end, 10);
        if (errno != 0 || end == slash + 1 || *end != '\0' || pl < 0) {
            return -1;
        }
        prefix_len = (uint8_t)pl;
    } else {
        prefix_len = 255;
    }

    memset(ip, 0, sizeof(*ip));
    memset(mask, 0, sizeof(*mask));

    /* Try v4 first. */
    struct in_addr addr4;
    if (inet_pton(AF_INET, buf, &addr4) == 1) {
        *ip_ver = 4;
        ip->v4 = ntohl(addr4.s_addr);
        if (prefix_len == 255) {
            prefix_len = 32;
        }
        if (!ipv4_mask_from_prefix(prefix_len, &mask->v4)) {
            return -1;
        }
        return 0;
    }

    /* Try v6. */
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, buf, &addr6) == 1) {
        *ip_ver = 6;
        memcpy(ip->v6, addr6.s6_addr, 16);
        if (prefix_len == 255) {
            prefix_len = 128;
        }
        if (!ipv6_mask_from_prefix(prefix_len, mask->v6)) {
            return -1;
        }
        return 0;
    }

    return -1;
}

static uint8_t parse_protocol(const char *val) {
    if (strcmp(val, "tcp") == 0) return 6;
    if (strcmp(val, "udp") == 0) return 17;
    if (strcmp(val, "icmp") == 0) return 1;
    if (strcmp(val, "icmpv6") == 0) return 58;

    errno = 0;
    char *end = NULL;
    long v = strtol(val, &end, 10);
    if (errno == 0 && end != val && *end == '\0' && v >= 0 && v <= 255) {
        return (uint8_t)v;
    }
    return 0;
}