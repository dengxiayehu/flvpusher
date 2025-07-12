#ifndef _RTMP_SOURCE_H_
#define _RTMP_SOURCE_H_

#include <librtmp/rtmp.h>
#include <xmedia.h>

#include "common/media_pusher.h"

using namespace xmedia;

namespace flvpusher {

class TagStreamerBase;

class RtmpSource : public MediaPusher {
public:
    RtmpSource(const std::string& input, MediaSink*& sink);
    virtual ~RtmpSource();

    virtual int loop();

private:
    struct MediaInfo {
        uint32_t vcodec_id, acodec_id;
        uint32_t w, h;
        uint32_t vrx, arx;
        uint32_t samplerate;
        uint32_t channel;
        FPSCalc fps;
        BitrateCalc vBC, aBC;
        int32_t tm_offset;

        MediaInfo() {
            vcodec_id = 0;
            acodec_id = 0;
            w = 0;
            h = 0;
            vrx = 0;
            arx = 0;
            samplerate = 0;
            channel = 0;
            tm_offset = 0;
        }
    };

private:
    int prepare();
    int disconnect();

private:
    RTMP* m_rtmp;
    uint32_t m_buffer_time;

    TagStreamerBase* m_vstrmer;
    TagStreamerBase* m_astrmer;
    TagStreamerBase* m_sstrmer;

    MediaInfo m_info;
};

}  // namespace flvpusher

#endif /* end of _RTMP_SOURCE_H_ */
