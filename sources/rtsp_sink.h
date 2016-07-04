#ifndef _RTSP_SINK_H_
#define _RTSP_SINK_H_

#include <xmedia.h>
#include <xqueue.h>
#include <xnet.h>

#include "media_sink.h"

namespace flvpusher {

class SubstreamDescriptor;
class RtspClient;
class MultiFramedRTPSink;
class Rtcp;

class RtspSink : public MediaSink {
public:
    RtspSink(const std::string &flvpath);
    virtual ~RtspSink();

    virtual Type type() const;

    virtual int connect(const std::string &liveurl);
    virtual int disconnect();

    virtual int send_video(int32_t timestamp, byte *dat, uint32_t length);
    virtual int send_audio(int32_t timestamp, byte *dat, uint32_t length);

private:
    void add_stream(MultiFramedRTPSink *rtp_sink);
    int check_and_set_destination();

private:
    DECL_THREAD_ROUTINE(RtspSink, proc_routine);
    xutil::RecursiveMutex m_mutex;
    xnet::AddressPort m_our_ap;
    std::string m_liveurl;
    xutil::Thread *m_proc_thrd;
    RtspClient *m_client;
    unsigned m_substream_sdp_sizes;
    std::vector<SubstreamDescriptor *> m_substream_descriptors;
    unsigned m_last_track_id;
    xutil::Queue<xmedia::Frame *> m_vqueue;
    xutil::Queue<xmedia::Frame *> m_aqueue;
    MultiFramedRTPSink *m_video_sink;
    MultiFramedRTPSink *m_audio_sink;
};

}

#endif /* end of _RTSP_SINK_H_ */
