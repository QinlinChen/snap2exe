#include "error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>

#define MAXLINE 4096

/*
 * Caller set this: zero if interactive, nonzero if daemon
 */
static int err_to_syslog = 0;

void set_err_to_stderr(void)
{
    err_to_syslog = 0;
}

void set_err_to_syslog(void)
{
    err_to_syslog = 1;
}

/*
 * Print a message and return to caller.
 * Caller specifies "errnoflag" and "priority".
 */
void err_doit(int errnoflag, int error, int priority,
              const char *fmt, ...)
{
    va_list ap;
    char buf[MAXLINE];

    va_start(ap, fmt);
    vsnprintf(buf, MAXLINE-1, fmt, ap);
    if (errnoflag)
        snprintf(buf+strlen(buf), MAXLINE-strlen(buf)-1, ": %s",
          strerror(error));
    strcat(buf, "\n");
    if (err_to_syslog) {
        syslog(priority, "%s", buf);
    } else {
        fflush(stdout);
        fputs(buf, stderr);
        fflush(stderr);
    }
    va_end(ap);
}