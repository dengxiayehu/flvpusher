#ifndef _MEDIA_SINK_H_
#define _MEDIA_SINK_H_

#include <string>
#include <xutil.h>

#include "flv_muxer.h"

namespace flvpusher {

class VideoRawParser;
class AudioRawParser;

class MediaSink {
public:
    MediaSink(const std::string &flvpath);
    virtual ~MediaSink();

    enum Type { RTMP_SINK, RTSP_SINK, HLS_SINK };
    virtual Type type() const = 0;

    virtual int connect(const std::string &liveurl) = 0;
    virtual int disconnect() = 0;

    virtual int send_video(int32_t timestamp, byte *dat, uint32_t length) = 0;
    virtual int send_audio(int32_t timestamp, byte *dat, uint32_t length) = 0;

protected:
    std::string m_url;

    VideoRawParser *m_vparser;
    AudioRawParser *m_aparser;
    FLVMuxer m_flvmuxer;

private:
    DISALLOW_COPY_AND_ASSIGN(MediaSink);
};

}

#endif /* end of _MEDIA_SINK_H_ */
