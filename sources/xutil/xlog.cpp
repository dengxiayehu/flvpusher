#include "xlog.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <pthread.h>
#include <cerrno>

#define COLOR_FORMAT_NONE           "\033[0m"
#define COLOR_FORMAT_LEVEL_WARNING  "\033[33;1m"
#define COLOR_FORMAT_LEVEL_ERROR    "\033[31;1m"
#define COLOR_FORMAT_LEVEL_INFO     "\033[37;0m"
#define COLOR_FORMAT_LEVEL_DEBUG    "\033[37;0m"
#define COLOR_FORMAT_LEVEL_LOG      "\033[37;0m"

using namespace xutil;

namespace xlog {

struct log_t {
    int fd;
    log_level lvl;
    int flgs;
    log_t *next;
};

static log_t *log;
static RecursiveMutex mutex;

static const char *color_level[] = {
    COLOR_FORMAT_LEVEL_DEBUG,
    COLOR_FORMAT_LEVEL_INFO,
    COLOR_FORMAT_LEVEL_WARNING,
    COLOR_FORMAT_LEVEL_ERROR
};

status_t log_add_dst(const char *logfile, log_level lvl, int flgs)
{
    AutoLock _l(mutex);

    int fd = open(logfile, O_WRONLY | O_CREAT | O_NOCTTY
            | (flgs&LOG_TRUNC ? O_TRUNC:O_APPEND), 0666);
    if (fd < 0) {
        fprintf(stderr, "Open \"%s\" failed: %s\n",
                logfile, ERRNOMSG);
        return ERR_SYS;
    }

    log_t *l = (log_t *) calloc(1, sizeof(log_t));
    if (!l) {
        fprintf(stderr, "calloc for log_t failed: %s\n",
                ERRNOMSG);
        close(fd);
        return ERR_SYS;
    }

    l->fd  = fd;
    l->lvl = lvl;
    l->flgs = flgs;

    // Link to global log list
    if (!log) {
        log = l;
    } else {
        l->next = log->next;
        log->next = l;
    }

    return SUCCESS;
}

void set_log_level(log_level lvl)
{
    AutoLock _l(mutex);

    for (log_t *l = log; l; l = l->next) {
        l->lvl = lvl;
    }
}

int log_print(const char *curfile, const int lineno, const log_level lvl,
        const char *fmt, ...)
{
    static const char *lvl_name[] = {"[DEBUG]", "[INFO]", "[WARN]", "[ERROR]"};

    AutoLock _l(mutex);

    for (log_t *l = log; l; l = l->next) {
        if (lvl < l->lvl) {
            // No need to log this line
            continue;
        }

        char time_buf[128] = {0};
        if (!(l->flgs&LOG_NODATE)) {
            struct timeval tv;
            if (-1 == gettimeofday(&tv, NULL)) {
                fprintf(stderr, "gettimeofday failed: %s", ERRNOMSG);
            } else {
                struct tm *ptm = localtime(&tv.tv_sec);
                snprintf(time_buf, sizeof(time_buf),
                        "%04d-%02d-%02d-%02d:%02d:%02d.%03ld ",
                        ptm->tm_year+1900, ptm->tm_mon+1, ptm->tm_mday,
                        ptm->tm_hour, ptm->tm_min, ptm->tm_sec,
                        tv.tv_usec/1000);
            }
        }

        char tid_buf[10] = {0};
        if (!(l->flgs&LOG_NOTID)) {
            snprintf(tid_buf, sizeof(tid_buf), "%ld ", gettid());
        }

        char buf[MaxLine];
        int ret = snprintf(buf, sizeof(buf), "%s%s%s[%s:%d] %s ",
                color_level[lvl],
                time_buf,
                tid_buf,
                curfile, lineno,
                lvl_name[lvl]);

        va_list ap;
        va_start(ap, fmt);
        ret = vsnprintf(buf + ret, sizeof(buf) - ret, fmt, ap);
        va_end(ap);

        strcat(buf, COLOR_FORMAT_NONE);

        if (!(l->flgs&LOG_NOLF))
            strcat(buf, "\n");

        if (l->flgs&LOG_STDERR)
            fprintf(stderr, "%s", buf);

        if (writen(l->fd, buf, strlen(buf)) < 0) {
            fprintf(stderr, "Write log failed: %s (cont)\n",
                    ERRNOMSG);
            // Fall through
        }
    }

    return SUCCESS;
}

status_t log_close()
{
    AutoLock _l(mutex);

    log_t *p = log, *q;
    while (p) {
        q = p->next;
        SAFE_CLOSE(p->fd);
        SAFE_FREE(p);
        p = q;
    }

    return SUCCESS;
}

}
