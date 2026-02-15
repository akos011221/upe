#ifndef RULE_CONFIG_H
#define RULE_CONFIG_H

#include "rule_table.h"

/*
    Load rules from INI config file into a rule table.
        Returns 0 on success, -1 on error.
*/
int rule_config_load(const char *path, rule_table_t *rt);

#endif