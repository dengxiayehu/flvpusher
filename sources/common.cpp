#include "common.h"

#include <librtmp/log.h>
#include <xlog.h>

namespace flvpusher {

void rtmp_log(int level, const char *fmt, va_list args)
{
    if (level == RTMP_LOGDEBUG2)
        return;

    char buf[4096];
    vsnprintf(buf, sizeof(buf)-1, fmt, args);

    switch (level) {
    default:
    case RTMP_LOGCRIT:
    case RTMP_LOGERROR:     level = xlog::ERR;   break;
    case RTMP_LOGWARNING:   level = xlog::WARN;  break;
    case RTMP_LOGINFO:      level = xlog::INFO;  break;
    case RTMP_LOGDEBUG:     level = xlog::DEBUG; break;
    }

    xlog::log_print("rtmp_module", -1, (xlog::log_level) level, buf);
}

}
