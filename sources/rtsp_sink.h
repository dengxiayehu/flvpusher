#ifndef _RTSP_SINK_H_
#define _RTSP_SINK_H_

#include <xmedia.h>
#include <xqueue.h>
#include <xnet.h>

#include "media_sink.h"
#include "rtsp_common.h"

namespace flvpusher {

class SubstreamDescriptor {
public:
    SubstreamDescriptor(MultiFramedRTPSink *rtp_sink, Rtcp *rtcp, unsigned track_id);
    ~SubstreamDescriptor();

    MultiFramedRTPSink *rtp_sink() const { return m_rtp_sink; }
    Rtcp *rtcp() const { return m_rtcp; }
    char const *sdp_lines() const { return m_sdp_lines; }

private:
    MultiFramedRTPSink *m_rtp_sink;
    Rtcp *m_rtcp;
    char *m_sdp_lines;
};

/////////////////////////////////////////////////////////////

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
    void add_stream(MultiFramedRTPSink *rtp_sink, Rtcp *rtcp);
    int set_destination_and_play();

    static void after_playing(void *client_data);

    struct MediaAggregation {
        xutil::Queue<xmedia::Frame *> queue;
        MultiFramedRTPSink *sink;
        Rtcp *rtcp;
        RtpInterface *rtp_socket;
        RtpInterface *rtcp_socket;

        MediaAggregation();
        ~MediaAggregation();
    };

private:
    xnet::AddressPort m_our_ap;
    DECL_THREAD_ROUTINE(RtspSink, proc_routine);
    xutil::Thread *m_proc_thrd;
    xutil::RecursiveMutex m_mutex;
    std::string m_liveurl;
    RtspClient *m_client;
    unsigned m_substream_sdp_sizes;
    std::vector<SubstreamDescriptor *> m_substream_descriptors;
    unsigned m_last_track_id;
    MediaAggregation *m_video, *m_audio;
};

}

#endif /* end of _RTSP_SINK_H_ */
