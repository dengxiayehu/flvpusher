#ifndef _HLS_PUSHER_H_
#define _HLS_PUSHER_H_

#include <xconfig.h>

#include "media_pusher.h"

namespace flvpusher {

class RtmpHandler;

class HLSPusher : public MediaPusher {
public:
    HLSPusher(const std::string &input, RtmpHandler *&rtmp_hdl, xconfig::Config *conf);
    virtual ~HLSPusher();

    int loop();

private:
    struct HLSStream {
        int id;
        int version;
        int sequence;
        float duration;
        float max_segment_length;
        uint64_t bandwidth;
        uint64_t size;
    };

    struct StreamSys {
        xconfig::Config *conf;
        std::string m3u8;

        std::vector<HLSStream *> streams;
        uint64_t bandwithd;

        struct HLSDownload {
            int stream;
            int segment;
            xutil::RecursiveMutex mutex;
            xutil::Condition wait;

            HLSDownload() : stream(0), segment(0), wait(mutex) { }
        } download;

        struct HLSPlayback {
            uint64_t offset;
            int stream;
            int segment;

            HLSPlayback() : offset(0), stream(0), segment(0) { }
        } playback;

        struct HLSPlaylist {
            uint64_t last;
            uint64_t wakeup;
            int tries;

            HLSPlaylist() : last(0), wakeup(0), tries(0) { }
        } playlist;

        struct HLSRead {
            xutil::RecursiveMutex mutex;
        } read;

        bool cache;
        bool meta;
        bool live;

        xutil::RecursiveMutex mutex;

        StreamSys(xconfig::Config *conf, std::string uri);
        ~StreamSys();
    };

private:
    int prepare();

    static int read_content_from_uri(int timeout, bool verbose, bool trace_ascii,
                                     const char *url, xutil::IOBuffer *iobuf);
    static int read_M3U8_from_uri(StreamSys *sys, const char *uri, xutil::IOBuffer *iobuf);

private:
    xconfig::Config *m_conf;
    StreamSys *m_sys;
    char *m_tempdir;
};

}

#endif /* end of _HLS_PUSHER_H_ */
