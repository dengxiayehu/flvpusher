#ifndef _RTMP_SOURCE_H_
#define _RTMP_SOURCE_H_

#include <librtmp/rtmp.h>
#include <xmedia.h>

#include "media_pusher.h"

using namespace xmedia;

namespace flvpusher {

class RtmpHandler;
class TagStreamerBase;

class RtmpSource : public MediaPusher {
public:
    RtmpSource(const std::string &input,
            RtmpHandler *&rtmp_hdl);
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
    };

private:
    int prepare();
    int disconnect();

private:
    RTMP *m_rtmp;
    uint32_t m_buffer_time;

    TagStreamerBase *m_vstrmer;
    TagStreamerBase *m_astrmer;
    TagStreamerBase *m_sstrmer;

    MediaInfo m_info;
};

}

#endif /* end of _RTMP_SOURCE_H_ */
