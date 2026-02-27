#define _POSIX_C_SOURCE 200809L
#include "rule_table.h"
#include <netinet/in.h>
#include <sys/socket.h>

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

/*
    Flush this rule into a table.
        Returns 0 on success, -1 on error.
*/
static int flush_rule(rule_t *r, bool *active, rule_table_t *rt, int line_num) {
    if (!*active) return 0;
    *active = false;

    if (r->action.type == ACT_FWD && r->action.out_ifindex == 0) {
        log_msg(LOG_ERROR, "rules:%d: fwd rule missing out_iface", line_num);
        return -1;
    }

    if (rule_table_add(rt, r) != 0) {
        log_msg(LOG_ERROR, "rules:%d: failed to add rule (table may be full)", line_num);
        return -1;
    }

    return 0;
}

int rule_config_load(const char *path, rule_table_t *rt) {
    if (!path || !rt) return -1;

    FILE *f = fopen(path, "r");
    if (!f) {
        log_msg(LOG_ERROR, "Unable to open rules file: %s: %s", path, strerror(errno));
        return -1;
    }

    char line[MAX_LINE];
    int line_num = 0;
    rule_t current;
    bool active = false;

    while (fgets(line, MAX_LINE, f)) {
        line_num++;

        /* Strip newline. */
        line[strcspn(line, "\r\n")] = '\0';
        char *s = strip(line);

        /* Skip empty lines and comments. */
        if (*s == '\0' || *s == '#' || *s == ';') continue;

        /* Section header. */
        if (*s == '[') {
            /* Flush previous rule. */
            if (flush_rule(&current, &active, rt, line_num) != 0) {
                fclose(f);
                return -1;
            }

            if (strncmp(s, "[rule]", 6) == 0) {
                memset(&current, 0, sizeof(current));
                active = true;
            } else {
                log_msg(LOG_ERROR, "rules:%d: unknown section header: %s", line_num, s);
                fclose(f);
                return -1;
            }
            continue;
        }

        if (!active) {
            log_msg(LOG_ERROR, "rules:%d: key=value outside [rule] section", line_num);
            fclose(f);
            return -1;
        }

        /* Parse key = value. */
        char *eq = strchr(s, '=');
        if (!eq) {
            log_msg(LOG_ERROR, "rules:%d: expected key = value", line_num);
            fclose(f);
            return -1;
        }

        *eq = '\0';
        char *key = strip(s);
        char *val = strip(eq + 1);

        if (strcmp(key, "priority") == 0) {
            errno = 0;
            char *end = NULL;
            long v = strtol(val, &end, 10);
            if (errno != 0 || end == val || *end != '\0' || v < 0) {
                log_msg(LOG_ERROR, "rules:%d: invalid priority: %s", line_num, val);
                fclose(f);
                return -1;
            }
            current.priority = (uint32_t)v;
        } else if (strcmp(key, "ip_version") == 0) {
            if (strcmp(val, "4") == 0)
                current.ip_ver = 4;
            else if (strcmp(val, "6") == 0)
                current.ip_ver = 6;
            else {
                log_msg(LOG_ERROR, "rules:%d: invalid ip_version: %s", line_num, val);
                fclose(f);
                return -1;
            }
        } else if (strcmp(key, "protocol") == 0) {
            current.protocol = parse_protocol(val);
        } else if (strcmp(key, "src") == 0) {
            uint8_t ver = 0;
            if (parse_ip_prefix(val, &ver, &current.src_ip, &current.src_mask) != 0) {
                log_msg(LOG_ERROR, "rules:%d: invalid src address: %s", line_num, val);
                fclose(f);
                return -1;
            }
            if (current.ip_ver == 0) current.ip_ver = ver;
        } else if (strcmp(key, "dst") == 0) {
            uint8_t ver = 0;
            if (parse_ip_prefix(val, &ver, &current.dst_ip, &current.dst_mask) != 0) {
                log_msg(LOG_ERROR, "rules:%d: invalid dst address: %s", line_num, val);
                fclose(f);
                return -1;
            }
            if (current.ip_ver == 0) current.ip_ver = ver;
        } else if (strcmp(key, "src_port") == 0) {
            errno = 0;
            char *end = NULL;
            long v = strtol(val, &end, 10);
            if (errno != 0 || end == val || *end != '\0' || v < 0 || v > 65535) {
                log_msg(LOG_ERROR, "rules:%d: invalid src_port: %s", line_num, val);
                fclose(f);
                return -1;
            }
            current.src_port = (uint16_t)v;
        } else if (strcmp(key, "dst_port") == 0) {
            errno = 0;
            char *end = NULL;
            long v = strtol(val, &end, 10);
            if (errno != 0 || end == val || *end != '\0' || v < 0 || v > 65535) {
                log_msg(LOG_ERROR, "rules:%d: invalid dst_port: %s", line_num, val);
                fclose(f);
                return -1;
            }
            current.dst_port = (uint16_t)v;
        } else if (strcmp(key, "action") == 0) {
            if (strcmp(val, "drop") == 0) {
                current.action.type = ACT_DROP;
            } else if (strcmp(val, "fwd") == 0) {
                current.action.type = ACT_FWD;
            } else {
                log_msg(LOG_ERROR, "rules:%d: invalid action: %s", line_num, val);
                fclose(f);
                return -1;
            }
        } else if (strcmp(key, "out_iface") == 0) {
            unsigned int idx = if_nametoindex(val);
            if (idx == 0) {
                log_msg(LOG_ERROR, "rules:%d: unknown interface: %s", line_num, val);
                fclose(f);
                return -1;
            }
            current.action.out_ifindex = (int)idx;
        } else {
            log_msg(LOG_ERROR, "rules:%d: unknown key: %s", line, key);
            fclose(f);
            return -1;
        }
    }

    /* Flush last rule. */
    if (flush_rule(&current, &active, rt, line_num) != 0) {
        fclose(f);
        return -1;
    }

    fclose(f);
    log_msg(LOG_INFO, "Loaded %zu rules from %s", rt->count, path);
    return 0;
}