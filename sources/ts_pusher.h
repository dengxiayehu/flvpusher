#ifndef _TS_PUSHER_H_
#define _TS_PUSHER_H_

#include <xmedia.h>

#include "media_pusher.h"

namespace flvpusher {

class TSParser;

class TSPusher : public MediaPusher {
public:
    TSPusher(const std::string &input,
            RtmpHandler *&rtmp_hdl);
    virtual ~TSPusher();

    int loop();

    virtual void ask2quit();

private:
    static int parsed_frame_cb(void *, xmedia::Frame *, int);

    int prepare();

    int send_metadata();

private:
    TSParser *m_parser;

    int32_t m_prev_ts;
    uint64_t m_tm_start;

    uint32_t m_width;
    uint32_t m_height;
};

}

#endif /* end of _TS_PUSHER_H_ */
