#ifndef _MEDIA_PUSHER_H_
#define _MEDIA_PUSHER_H_

#include <string>

#include <xmedia.h>
#include <xfile.h>

#include "ts_muxer.h"

namespace flvpusher {

class MediaSink;

class MediaPusher {
public:
    MediaPusher(const std::string &input, MediaSink *&sink);
    virtual ~MediaPusher();

    virtual void ask2quit() { m_quit = true; }
    virtual int loop() = 0;

    int dump_video(const std::string &path, bool append = false);
    int dump_audio(const std::string &path, bool append = false);
    int mux2ts(const std::string &tspath);

    virtual int on_frame(const int32_t ts,
                         const byte *dat, const uint32_t dat_len, int is_video);

protected:
    void set_itime_base(AVRational tb) { m_itime_base = tb; }

protected:
    std::string m_input;
    MediaSink *m_sink;
    volatile bool m_quit;

    xfile::File m_dvf;
    xfile::File m_daf;
    std::string m_tspath;

private:
    AVRational m_itime_base;
    TSMuxer m_tsmuxer;

    xutil::RecursiveMutex m_mutex;
};

}

#endif /* end of _MEDIA_PUSHER_H_ */
