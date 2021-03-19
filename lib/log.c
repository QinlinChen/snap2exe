#include "sys.h"
#include "config.h"
#include "log.h"

#include <stdarg.h>
#include <time.h>

#include "utils.h"

#define LEVEL_LT(lhs, rhs) ((lhs) < (rhs))

static FILE *_logfp = NULL;
static const char *_log_identity = "origin";

static FILE *get_logfp();
static int get_logfd();

int init_log()
{
    if (_logfp)
        return 0;
    _logfp = fopen(config.log_file, "a");
    return _logfp ? 0 : -1;
}

int reinit_log()
{
    if (_logfp)
        fclose(_logfp);
    _logfp = fopen(config.log_file, "a");
    return _logfp ? 0 : -1;
}

static FILE *get_logfp()
{
    if (!_logfp && init_log() != 0)
        return NULL;
    return _logfp;
}

static int get_logfd()
{
    FILE *logfp = get_logfp();
    if (!logfp)
        return -1;
    return fileno(logfp);
}

void lock_logfile()
{
    int logfd = get_logfd();
    if (logfd == -1)
        return;
    lock_reg(logfd, F_SETLKW, F_WRLCK, 0, SEEK_SET, 0);
}

void unlock_logfile()
{
    int logfd = get_logfd();
    if (logfd == -1)
        return;
    lock_reg(logfd, F_SETLK, F_UNLCK, 0, SEEK_SET, 0);
}

void set_log_identity(const char *new_identity)
{
    _log_identity = new_identity;
}

static char *read_time(char *buf, int size)
{
    time_t t;

    time(&t);
    if (strftime(buf, size, "%b %d %T", localtime(&t)) == 0)
        snprintf(buf, size, "time error");

    return buf;
}

static char *read_cmdline(char *buf, size_t size)
{
    FILE *fp;

    if ((fp = fopen("/proc/self/cmdline", "r")) == NULL)
        goto err_out;

    memset(buf, -1, size);
    if (readline(fp, buf, size) == (char *)-1)
        goto close_and_err_out;
    fclose(fp);

    int i = size - 1;
    while (buf[i] == (char)-1)
        --i;
    for (--i; i >=0; --i)
        if (buf[i] == '\0')
            buf[i] = ' ';
    return buf;

close_and_err_out:
    fclose(fp);
err_out:
    snprintf(buf, size, "comm error");
    return buf;
}

void log_without_lock(int level, const char *format, ...)
{
    if (LEVEL_LT(level, config.log_level))
        return;

    FILE *fp;
    if (!(fp = get_logfp()))
        return;

    char prefix[MAXLINE], tm[64], comm[MAXLINE];
    snprintf(prefix, ARRAY_LEN(prefix), "[%s %s %s(%ld)](%s)",
             level_to_str(level), read_time(tm, ARRAY_LEN(tm)),
             _log_identity, (long)getpid(),
             read_cmdline(comm, ARRAY_LEN(comm)));

    char text[MAXLINE];
    va_list ap;
    va_start(ap, format);
    vsnprintf(text, ARRAY_LEN(text), format, ap);
    va_end(ap);

    /* Do fprintf all at once to keep atomicity if possible. */
    fprintf(fp, "%s%s", prefix, text);
    fflush(fp);
}

const char *level_to_str(int level)
{
    switch (level) {
    case LEVEL_DEBUG:   return "DEBUG";
    case LEVEL_INFO:    return "INFO ";
    case LEVEL_WARN:    return "WARN ";
    case LEVEL_ERROR:   return "ERROR";
    case LEVEL_FATAL:   return "FATAL";
    default:
        break;
    }
    return "UNKNOWN";
}

int str_to_level(const char *str)
{
    if (strcmp(str, "DEBUG") == 0)
        return LEVEL_DEBUG;
    if (strcmp(str, "INFO") == 0)
        return LEVEL_INFO;
    if (strcmp(str, "WARN") == 0)
        return LEVEL_WARN;
    if (strcmp(str, "ERROR") == 0)
        return LEVEL_ERROR;
    if (strcmp(str, "FATAL") == 0)
        return LEVEL_FATAL;
    return -1;
}