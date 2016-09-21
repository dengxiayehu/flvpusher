#ifndef _XLOG_H_
#define _XLOG_H_

#include <cstdarg>

#define LOGD(fmt, ...) do { \
  xlog::log_print(__FILE__, __LINE__, xlog::DEBUG, fmt, ##__VA_ARGS__); \
} while (0)

#define LOGI(fmt, ...) do { \
  xlog::log_print(__FILE__, __LINE__, xlog::INFO, fmt, ##__VA_ARGS__); \
} while (0)

#define LOGW(fmt, ...) do { \
  xlog::log_print(__FILE__, __LINE__, xlog::WARN, fmt, ##__VA_ARGS__); \
} while (0)

#define LOGE(fmt, ...) do { \
  xlog::log_print(__FILE__, __LINE__, xlog::ERR, fmt, ##__VA_ARGS__); \
} while (0)

#include "xutil.h"

using xutil::status_t;

namespace xlog {

enum log_level {
  DEBUG,
  INFO,
  WARN,
  ERR
};

#define LOG_TRUNC       1
#define LOG_NODATE      (1<<1)
#define LOG_NOLF        (1<<2)
#define LOG_NOLVL       (1<<3)
#define LOG_STDERR      (1<<4)
#define LOG_NOTID       (1<<5)
#define LOG_DEFAULT     (LOG_STDERR | LOG_TRUNC)

status_t log_add_dst(const char *logfile,
                     log_level lvl = DEBUG, int flgs = LOG_DEFAULT);
int set_log_level(log_level lvl);
int set_log_level(const char *lvlstr);
int log_print(const char *curfile, const int lineno, const log_level lvl,
              const char *fmt, ...);
status_t log_close();

}

#endif /* end of _XLOG_H_ */
