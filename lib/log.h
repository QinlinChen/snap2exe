#ifndef _LOG_H
#define _LOG_H

#include <stdio.h>
#include <string.h>

enum {
    LEVEL_DEBUG, LEVEL_INFO, LEVEL_WARN, LEVEL_ERROR, LEVEL_FATAL
};

int init_log();
int reinit_log();
void set_log_identity(const char *new_identity);
void lock_logfile();
void unlock_logfile();
void log_without_lock(int level, const char *format, ...);

int str_to_level(const char *str);
const char *level_to_str(int level);

#define log_debug(format, ...) \
    do { \
        log_without_lock(LEVEL_DEBUG, format "\n", ## __VA_ARGS__); \
    } while (0)

#define log_info(format, ...) \
    do { \
        log_without_lock(LEVEL_INFO, format "\n", ## __VA_ARGS__); \
    } while (0)

#define log_warn(format, ...) \
    do { \
        log_without_lock(LEVEL_WARN, format "\n", ## __VA_ARGS__); \
    } while (0)

#define log_error(format, ...) \
    do { \
        log_without_lock(LEVEL_ERROR, format "\n", ## __VA_ARGS__); \
    } while (0)

#define log_fatal(format, ...) \
    do { \
        log_without_lock(LEVEL_FATAL, format "\n", ## __VA_ARGS__); \
    } while (0)

#define log_unix_error(format, ...) \
    do { \
        log_without_lock(LEVEL_ERROR, format ": %s\n", ## __VA_ARGS__, \
                         strerror(errno)); \
    } while (0)

#endif /* _LOG_H */