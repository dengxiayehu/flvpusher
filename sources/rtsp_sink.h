#ifndef _RTSP_SINK_H_
#define _RTSP_SINK_H_

#include "media_sink.h"

namespace flvpusher {

class RtspSink : public MediaSink {
public:
    RtspSink(const std::string &flvpath);
    virtual ~RtspSink();

    virtual Type type() const;

    virtual int connect(const std::string &liveurl);
    virtual int disconnect();

    virtual int send_video(int32_t timestamp, byte *dat, uint32_t length);
    virtual int send_audio(int32_t timestamp, byte *dat, uint32_t length);
};

}

#endif /* end of _RTSP_SINK_H_ */
