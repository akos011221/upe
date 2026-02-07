#define _POSIX_C_SOURCE 200112L

#include "benchmark_test.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
                    // Trim trailing newline.
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

    // Parse cache sizes from /sys/devices/system/cpu/cpu0/cache/.
    // Each index*/ contains: type, level, size.

    // L1 data cache (index0).
    f = fopen("/sys/devices/system/cpu/cpu0/cache/index0/size", "r");
    if (f) {
        if (fscanf(f, "%dK", &info->l1d_cache_kb) != 1) {
            info->l1d_cache_kb = 0;
        }
        fclose(f);
    }

    // L2 cache (index2).
    f = fopen("/sys/devices/system/cpu/cpu0/cache/index2/size", "r");
    if (f) {
        if (fscanf(f, "%dK", &info->l2_cache_kb) != 1) {
            info->l2_cache_kb = 0;
        }
        fclose(f);
    }

    // L3 cache (index3).
    f = fopen("/sys/devices/system/cpu/cpu0/cache/index3/size", "r");
    if (f) {
        if (fscanf(f, "%dK", &info->l3_cache_kb) != 1) {
            info->l3_cache_kb = 0;
        }
        fclose(f);
    }

    // NUMA nodes: count directories in /sys/devices/system/node/.
    // Dirs are named node0, node1...
    int numa_count = 0;
    char path[64];

    for (int i = 0;; i++) {
        snprintf(path, sizeof(path), "/sys/devices/system/node/node%d", i);
        if (access(path, F_OK) != 0) {
            break;
        }
        numa_count++;
    }

    info->numa_nodes = numa_count > 0 ? numa_count : 1;
}

/*
    JSON Output helpers.
*/

void json_init(json_ctx_t *ctx, FILE *out) {
    ctx->out = out;
    ctx->indent_level = 0;
    ctx->needs_comma = false;
}

static void json_print_indent(json_ctx_t *ctx) {
    for (int i = 0; i < ctx->indent_level; i++) {
        fprintf(ctx->out, "    ");
    }
}

void json_begin_object(json_ctx_t *ctx) {
    if (ctx->needs_comma) {
        fprintf(ctx->out, ",\n");
    }
    json_print_indent(ctx);
    fprintf(ctx->out, "{\n");
    ctx->indent_level++;
    ctx->needs_comma = false;
}

void json_end_object(json_ctx_t *ctx) {
    fprintf(ctx->out, "\n");
    ctx->indent_level--;
    json_print_indent(ctx);
    fprintf(ctx->out, "}");
    ctx->needs_comma = true;
}

void json_key_string(json_ctx_t *ctx, const char *key, const char *value) {
    if (ctx->needs_comma) {
        fprintf(ctx->out, ",\n");
    }
    json_print_indent(ctx);
    fprintf(ctx->out, "\"%s\": \"%s\"", key, value);
    ctx->needs_comma = true;
}

void json_key_int(json_ctx_t *ctx, const char *key, int64_t value) {
    if (ctx->needs_comma) {
        fprintf(ctx->out, ",\n");
    }
    json_print_indent(ctx);
    fprintf(ctx->out, "\"%s\": %ld", key, (long)value);
    ctx->needs_comma = true;
}

void json_key_double(json_ctx_t *ctx, const char *key, double value) {
    if (ctx->needs_comma) {
        fprintf(ctx->out, ",\n");
    }
    json_print_indent(ctx);
    fprintf(ctx->out, "\"%s\": %.6f", key, value);
    ctx->needs_comma = true;
}

void json_key_bool(json_ctx_t *ctx, const char *key, bool value) {
    if (ctx->needs_comma) {
        fprintf(ctx->out, ",\n");
    }
    json_print_indent(ctx);
    fprintf(ctx->out, "\"%s\": %s", key, value ? "true" : "false");
    ctx->needs_comma = true;
}

void json_begin_nested_object(json_ctx_t *ctx, const char *key) {
    if (ctx->needs_comma) {
        fprintf(ctx->out, ",\n");
    }
    json_print_indent(ctx);
    fprintf(ctx->out, "\"%s\": {\n", key);
    ctx->indent_level++;
    ctx->needs_comma = false;
}

/*
    Timing related.
*/

double benchmark_get_time(void) {
    struct timespec ts;

    // CLOCK_MONOTONIC_RAW is not affected by NTP adjustments.
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) {
        perror("clock_gettime(CLOCK_MONOTONIC_RAW)");
        exit(EXIT_FAILURE);
    }

    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

double benchmark_measure_timing_overhead(void) {
    const int iterations = 100000;
    double start = benchmark_get_time();

    for (int i = 0; i < iterations; i++) {
        (void)benchmark_get_time();
    }

    double end = benchmark_get_time();
    double total_sec = end - start;
    double overhead_sec = total_sec / (double)iterations;
    double overhead_ns = overhead_sec * 1e9;

    return overhead_ns;
}

/*
    CLI Argument Parsing.
*/

size_t benchmark_parse_size_t(const char *option_name) {
    char *endptr;
    errno = 0;

    unsigned long val = strtoul(optarg, &endptr, 10);

    if (errno == ERANGE || endptr == optarg || *endptr != '\0') {
        fprintf(stderr, "Error: Invalid value for --%s: '%s'\n", option_name, optarg);
        exit(EXIT_FAILURE);
    }

    return (size_t)val;
}

int benchmark_parse_int(const char *option_name) {
    char *endptr;
    errno = 0;

    long val = strtol(optarg, &endptr, 10);

    if (errno == ERANGE || endptr == optarg || *endptr != '\0') {
        fprintf(stderr, "Error: Invalid value for --%s: '%s'\n", option_name, optarg);
        exit(EXIT_FAILURE);
    }

    if (val > INT_MAX || val < INT_MIN) {
        fprintf(stderr, "Error: Value for --%s is out of range: %ld\n", option_name, val);
        exit(EXIT_FAILURE);
    }

    return (int)val;
}

double benchmark_parse_double(const char *option_name) {
    char *endptr;
    errno = 0;

    double val = strtod(optarg, &endptr);

    if (errno == ERANGE || endptr == optarg || *endptr != '\0') {
        fprintf(stderr, "Error: Invalid value for --%s: '%s'\n", option_name, optarg);
        exit(EXIT_FAILURE);
    }

    return val;
}

/*
    Variance Calculation.
*/

void benchmark_calculate_variance(const double *values, int count, double *mean, double *cv) {
    if (count <= 0) {
        *mean = 0.0;
        *cv = 0.0;
        return;
    }

    // Mean:
    double sum = 0.0;
    for (int i = 0; i < count; i++) {
        sum += values[i];
    }
    *mean = sum / (double)count;

    // Deviation:
    double variance = 0.0;
    for (int i = 0; i < count; i++) {
        double diff = values[i] - *mean;
        variance += diff * diff;
    }
    variance /= (double)count;
    double stddev = sqrt(variance);

    // Coefficient of variation:
    *cv = (*mean != 0.0) ? (stddev / *mean) : 0.0;
}