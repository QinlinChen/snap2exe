#ifndef _ERROR_H
#define _ERROR_H

#include <errno.h>
#include <syslog.h>

void set_err_to_stderr(void);
void set_err_to_syslog(void);

void err_doit(int errnoflag, int error, int priority,
              const char *fmt, ...);

#define unix_err(fmt, ...) \
    do { \
        err_doit(1, errno, LOG_ERR, "[%s,%d,%s] " fmt, \
            __FILE__, __LINE__, __func__, ## __VA_ARGS__); \
    } while (0)

#define unix_errq(fmt, ...) \
    do { \
        err_doit(1, errno, LOG_ERR, "[%s,%d,%s] " fmt, \
            __FILE__, __LINE__, __func__, ## __VA_ARGS__); \
        exit(1); \
    } while (0)

#define app_err(fmt, ...) \
    do { \
        err_doit(0, 0, LOG_ERR, "[%s,%d,%s] " fmt, \
            __FILE__, __LINE__, __func__, ## __VA_ARGS__); \
    } while (0)

#define app_errq(fmt, ...) \
    do { \
        err_doit(0, 0, LOG_ERR, "[%s,%d,%s] " fmt, \
            __FILE__, __LINE__, __func__, ## __VA_ARGS__); \
        exit(1); \
    } while (0)

#define posix_err(error, fmt, ...) \
    do { \
        err_doit(1, (error), LOG_ERR, "[%s,%d,%s] " fmt, \
            __FILE__, __LINE__, __func__, ## __VA_ARGS__); \
    } while (0)

#define posix_errq(error, fmt, ...) \
    do { \
        err_doit(1, (error), LOG_ERR, "[%s,%d,%s] " fmt, \
            __FILE__, __LINE__, __func__, ## __VA_ARGS__); \
        exit(1); \
    } while (0)

#endif