#include "rule_table.h"

#include <stdlib.h>
#include <string.h>

/*
    Helper to create 32-bit mask from prefix length
    e.g. 17 -> 0xffff8000

    NOTE: Shifting a value by >= its bit width is undefined behavior
          thus prefix_len=0 is handled separetely.
          prefix_len=32 is valid to shift, but also handled seperately.
*/
bool ipv4_mask_from_prefix(uint8_t prefix_len, uint32_t *out_mask) {
    if (!out_mask) return false;
    if (prefix_len > 32) return false;

    if (prefix_len == 0) {
        *out_mask = 0;
        return true;
    }

    if (prefix_len == 32) {
        *out_mask = 0xffffffffu;
        return true;
    }

    *out_mask = (uint32_t)(0xffffffffu << (32 - prefix_len));
    return true;
}

bool ipv6_mask_from_prefix(uint8_t prefix_len, uint8_t out_mask[16]) {
    if (!out_mask) return false;
    if (prefix_len > 128) return false;

    memset(out_mask, 0, 16);

    uint8_t full_bytes = prefix_len / 8;
    uint8_t remaining_bits = prefix_len % 8;

    for (uint8_t i = 0; i < full_bytes; i++) {
        out_mask[i] = 0xff;
    }

    if (remaining_bits > 0 && full_bytes < 16) {
        out_mask[full_bytes] = (uint8_t)(0xff << (8 - remaining_bits));
    }

    return true;
}

static inline bool match_ipv6(const uint8_t pkt_ip[16], const uint8_t rule_ip[16],
                              const uint8_t mask[16]) {
    for (int i = 0; i < 16; i++) {
        if ((pkt_ip[i] & mask[i]) != (rule_ip[i] & mask[i])) {
            return false;
        }
    }
    return true;
}

/*
    Bit masking to match IP address.

    NOTE: If mask=0, both sides become 0 => match is always true (wildcard)
*/
static inline bool match_ip(uint32_t pkt_ip, uint32_t rule_ip, uint32_t mask) {
    return (pkt_ip & mask) == (rule_ip & mask);
}

/*
    Match rule against a packet 5-tuple.

    Cheap checks must come first, more expensive ones later for performance.
*/
static inline bool match_rule(const rule_t *r, const flow_key_t *k) {
    if (r->ip_ver != 0 && r->ip_ver != k->ip_ver) return false;
    if (r->protocol && r->protocol != k->protocol) return false;
    if (r->src_port && r->src_port != k->src_port) return false;
    if (r->dst_port && r->dst_port != k->dst_port) return false;

    if (k->ip_ver == 4) {
        if (!match_ip(k->src_ip.v4, r->src_ip.v4, r->src_mask.v4)) return false;
        if (!match_ip(k->dst_ip.v4, r->dst_ip.v4, r->dst_mask.v4)) return false;
    } else if (k->ip_ver == 6) {
        // TODO
    }

    return true;
}

/*
    Compare two rules by priority. Lower priority wins.
*/
static int rule_priority_cmp(const void *a, const void *b) {
    const rule_t *ra = (const rule_t *)a;
    const rule_t *rb = (const rule_t *)b;

    if (ra->priority < rb->priority) return -1;
    if (ra->priority > rb->priority) return 1;

    /* Tie breaker:
       If priorities are equal, check rule_id (insertion order) */
    if (ra->rule_id < rb->rule_id) return -1;
    if (ra->rule_id > rb->rule_id) return 1;

    return 0;
}

int rule_table_init(rule_table_t *t, size_t capacity) {
    if (!t || capacity == 0) return -1;

    t->rules = (rule_t *)calloc(capacity, sizeof(rule_t));
    if (!t->rules) return -1;

    t->count = 0;
    t->capacity = capacity;
    return 0;
}

void rule_table_destroy(rule_table_t *t) {
    if (!t) return;
    free(t->rules);
    t->rules = NULL;
    t->count = 0;
    t->capacity = 0;
}

int rule_table_add(rule_table_t *t, const rule_t *r_in) {
    if (!t || !t->rules || !r_in) return -1;
    if (t->count >= t->capacity) return -1;

    /* Copy incoming rule (struct copy, field-by-field by compiler) */
    rule_t r = *r_in;

    /* Assign stable rule ID by insertion order */
    r.rule_id = (uint32_t)t->count;

    /* If mask=0 (wildcard), src_ip, dst_ip don't matter */
    if (r.ip_ver == 4 && r.src_mask.v4 == 0) r.src_ip.v4 = 0;
    if (r.ip_ver == 4 && r.dst_mask.v4 == 0) r.dst_ip.v4 = 0;

    t->rules[t->count++] = r;

    /* Keep table sorted by priority after each insertion */
    qsort(t->rules, t->count, sizeof(rule_t), rule_priority_cmp);

    return 0;
}

const rule_t *rule_table_match(const rule_table_t *t, const flow_key_t *k) {
    if (!t || !t->rules || !k) return NULL;

    /* Get the first match => highest priority
       PERFORMANCE: O(N_rules) worst case, O(1) best case (first match) */
    for (size_t i = 0; i < t->count; i++) {
        const rule_t *r = &t->rules[i];
        if (match_rule(r, k)) {
            return r;
        }
    }

    return NULL;
}