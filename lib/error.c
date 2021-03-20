#include "sys.h"
#include "config.h"
#include "snap2exe/snap2exe.h"

#include <stdarg.h>

static char errmsg_buf[MAXBUF]; /* TODO: make it thread local. */

char *s2e_errmsg(char *buf, size_t len)
{
    strncpy(buf, errmsg_buf, len);
    buf[len - 1] = '\0';
    return buf;
}

void s2e_set_errmsg(int errnoflag, int error, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(errmsg_buf, MAXBUF, fmt, ap);
    if (errnoflag)
        snprintf(errmsg_buf + strlen(errmsg_buf), MAXBUF - strlen(errmsg_buf),
                 ": %s", strerror(error));
    va_end(ap);
}
