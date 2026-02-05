#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

// Collect system information.
typedef struct {
    char cpu_model[256]; // e.g. "Intel(R) Xeon(R) CPU E5-2680 v4"
    int num_cores;       // Total logical CPUs (includes hyper-threading)
    int l1d_cache_kb;    // L1 data cache size in KB (per core)
    int l2_cache_kb;     // L2 cache size in KB (per core)
    int l3_cache_kb;     // L3 cache size in KB (shared)
    int numa_nodes;      // Number of NUMA nodes (1 = UMA system)
} system_info_t;

/*
    Fill system_info_t by reading /proc and /sys.
*/
void benchmark_get_system_info(system_info_t *info);

/*
    JSON Output helpers.
*/

typedef struct {
    FILE *out;        // Output stream (stdout or file)
    int indent_level; // Current nesting depth (0 = top level)
    bool needs_comma;
} json_ctx_t;

void json_init(json_ctx_t *ctx, FILE *out);
void json_begin_object(json_ctx_t *ctx); // Prints '{'
void json_end_object(json_ctx_t *ctx);   // Prints '}'
void json_key_string(json_ctx_t *ctx, const char *key, const char *value);
void json_key_int(json_ctx_t *ctx, const char *key, int value);
void json_key_double(json_ctx_t *ctx, const char *key, double value);
void json_key_bool(json_ctx_t *ctx, const char *key, bool value);
void json_begin_nested_object(json_ctx_t *ctx, const char *key);

/*
    Get current timestamp using CLOCK_MONOTONIC_RAW.
        Returns time in seconds (double precision).
*/
double benchmark_get_time(void);

/*
    Measure the overhead of benchmark_get_time().
    This is to substract the clock call overhead from the total time.
        Returns overhead in nanoseconds.
*/
double benchmark_measure_timing_overhead(void);

/*
    CLI Argument Parsing.
*/

size_t benchmark_parse_size_t(const char *option_name);
int benchmark_parse_int(const char *option_name);
double benchmark_parse_double(const char *option_name);

/*
    Variance Calculation.

    - High variance means that some threads are slower than others
    - May be the sign of contention (lock/CAS conflicts)
    - CPU scheduling issue: threads migrating across cores

    Metric used is: Coefficient of Variation (CV) = stddev / mean
    - CV < 0.05 (5%): Very good load balance
    - CV 0.05-0.15: OK
    - CV > 0.15: Not good. Contention, affinity issues, unbalanced work distribution?
*/

/*
    Calculate mean and coefficient of variation from per-thread results.

    Inputs:
        values: Arary of per-thread throughputs (ops/sec)
        count: Number of threads

    Outputs:
        mean: Avarage throughput across threads
        cv: Coefficient of variation (stddev / mean)
*/
void benchmark_calculate_variance(const double *values, int count, double *mean, double *cv);

#endif