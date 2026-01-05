#ifndef RULE_TABLE_H
#define RULE_TABLE_H

#include <stdbool.h>
#include <stdint.h>

#include "parser.h"

typedef enum {
    ACT_DROP = 0,
    ACT_FWD = 1
} action_type_t;

typedef struct {
    action_type_t type;
    int out_ifindex; // linux interface index for TX
} flow_action_t;

typedef struct {
    uint32_t priority; // lower is higher priority

    uint32_t src_ip;
    uint32_t src_mask;
    uint32_t dst_ip;
    uint32_t dst_mask;

    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;

    flow_action_t action;

    uint32_t rule_id; // assigned by rule table at rule insert
} rule_t;

typedef struct {
    rule_t *rules;
    size_t count;
    size_t capacity;
} rule_table_t;

/* Initialize a rule table (dynamic array)
   Returns 0 if successful, -1 if not. */
int rule_table_init(rule_table_t *t, size_t capacity);

/* Destroy a rule table and free memory */
void rule_table_destroy(rule_table_t *t);

/* Add rule, the table will contain a copy of the rule & assign rule id
   Rules are sorted by priority after insertion
   Returns 0 if successful, -1 if not. */
int rule_table_add(rule_table_t *t, const rule_t *r_in);

/* Return the first matching rule (highest priority due to sorting).
   Returns matching rule_t or NULL if no match */
const rule_t *rule_table_match(const rule_table_t *t, const flow_key_t *k);

/* Helper to build a prefix mask (e.g. 17 -> 255.255.128.0).
   Returns false if prefix is invalid (e.g. >32),
   otherwise writes the mask to out_mask and returns true */
bool ipv4_mask_from_prefix(uint8_t prefix_len, uint32_t *out_mask);

#endif