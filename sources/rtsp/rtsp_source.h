#ifndef _RTSP_SOURCE_H_
#define _RTSP_SOURCE_H_

#include <xnet.h>

#include "common/media_pusher.h"

using namespace xnet;

namespace flvpusher {

class RtspClient;

class RtspSource : public MediaPusher {
public:
  RtspSource(const std::string &input, MediaSink *&sink);
  virtual ~RtspSource();

  virtual int loop();

  virtual int on_frame(const int32_t ts,
                       const byte *dat, const uint32_t dat_len, int is_video);

private:
  int prepare();

private:
  RtspClient *m_client;
};

};


#endif /* end of _RTSP_SOURCE_H_ */
