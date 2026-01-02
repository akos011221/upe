#include "log.h"

#include <stdio.h>
#include <time.h>

static log_level_t g_level = LOG_INFO;

void log_level_set(log_level_t level)
{
    g_level = level;
}

static const char *level_to_string(log_level_t level)
{
    switch (level)
    {
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