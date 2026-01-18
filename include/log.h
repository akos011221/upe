#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <stddef.h>

typedef enum {
    LOG_ERROR = 0,
    LOG_WARN = 1,
    LOG_INFO = 2,
    LOG_DEBUG = 3
} log_level_t;

void log_set_level(log_level_t level);

/*
  printf-style logging.
  Example:
    log_msg(LOG_INFO, "Listening on %s", iface);
*/
void log_msg(log_level_t level, const char *fmt, ...);

/* Print hexdump of a memory region. */
void log_hexdump(log_level_t level, const void *data, size_t len);

#endif