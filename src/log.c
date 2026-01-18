#define _POSIX_C_SOURCE 200809L
#include "log.h"

#include <stdio.h>
#include <time.h>

static log_level_t g_level = LOG_INFO;

void log_set_level(log_level_t level) {
    g_level = level;
}

static const char *level_to_string(log_level_t level) {
    switch (level) {
    case LOG_ERROR:
        return "ERROR";
    case LOG_WARN:
        return "WARN";
    case LOG_INFO:
        return "INFO";
    case LOG_DEBUG:
        return "DEBUG";
    default:
        return "UNKNOWN";
    }
}

void log_msg(log_level_t level, const char *fmt, ...) {
    if (level > g_level) {
        return;
    }

    // Timestamp
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);

    char tbuf[32];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm_now);

    // Print prefix
    fprintf(stderr, "%s [%s] ", tbuf, level_to_string(level));

    // Variadic printing
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\n");
}

void log_hexdump(log_level_t level, const void *data, size_t len) {
    if (level > g_level) {
        return;
    }

    const unsigned char *p = (const unsigned char *)data;

    for (size_t i = 0; i < len; i += 16) {
        fprintf(stderr, "%04zx  ", i); // Offset

        // Hex bytes
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len)
                fprintf(stderr, "%02x  ", p[i + j]);
            else
                fprintf(stderr, "    ");
        }

        // ASCII characters
        fprintf(stderr, " |");
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                unsigned char c = p[i + j];
                // Print printable chars, otherwise dot
                fprintf(stderr, "%c", (c >= 32 && c <= 126) ? c : '.');
            }
        }
        fprintf(stderr, "|\n");
    }
}