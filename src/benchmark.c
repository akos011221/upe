#define _POSIX_C_SOURCE 200112L

#include "benchmark.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void benchmark_get_system_info(system_info_t *info) {
    memset(info, 0, sizeof(*info));

    // Default values (if parsing fails).
    info->num_cores = 1;
    info->numa_nodes = 1;

    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[512];
        int cpu_count = 0;

        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "model name", 10) == 0 && info->cpu_model[0] == '\0') {
                char *colon = strchr(line, ':');
                if (colon) {
                    colon += 2; // Skip ": "
                    // Trim trailing newline
                    size_t len = strlen(colon);
                    if (len > 0 && colon[len - 1] == '\n') {
                        colon[len - 1] = '\0';
                    }
                    strncpy(info->cpu_model, colon, sizeof(info->cpu_model) - 1);
                }
            }

            // Count processors.
            if (strncmp(line, "processor", 9) == 0) {
                cpu_count++;
            }
        }

        info->num_cores = cpu_count;
        fclose(f);
    }
}