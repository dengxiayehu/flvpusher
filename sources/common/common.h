#ifndef _COMMON_H_
#define _COMMON_H_

#include <vector>
#include <cstdarg>

#include <xtype.h>

namespace flvpusher {

typedef std::pair<uint32_t, byte *> NaluItem;
typedef struct Nalu {
  std::vector<NaluItem *> *dat;
} Nalu;

void rtmp_log(int level, const char *fmt, va_list args);

enum RTMPChannel {
  RTMP_NETWORK_CHANNEL = 2,
  RTMP_SYSTEM_CHANNEL,
  RTMP_AUDIO_CHANNEL,
  RTMP_VIDEO_CHANNEL   = 6,
  RTMP_SOURCE_CHANNEL  = 8,
};

}

#endif /* end of _COMMON_H_ */
