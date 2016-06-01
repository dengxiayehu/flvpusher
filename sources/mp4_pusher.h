#ifndef _MP4_PUSHER_H_
#define _MP4_PUSHER_H_

#include <xutil.h>

#include "media_pusher.h"

namespace flvpusher {

class RtmpHandler;
class MP4Parser;

class MP4Pusher : public MediaPusher {
public:
    MP4Pusher(const std::string &input,
            RtmpHandler *&rtmp_hdl);
    virtual ~MP4Pusher();

    int loop();

private:
    DECL_THREAD_ROUTINE(MP4Pusher, vsnd_func);
    DECL_THREAD_ROUTINE(MP4Pusher, asnd_func);

private:
    int prepare();
    int send_metadata();

private:
    xutil::Thread *m_vthrd;
    xutil::Thread *m_athrd;

    MP4Parser *m_parser;
    xutil::RecursiveMutex m_mutex;

    uint64_t m_tm_start;
    int m_retval;
};

}

#endif /* end of _MP4_PUSHER_H_ */
