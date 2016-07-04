#include <xlog.h>
#include <memory>
#include <xuri.h>

#include "rtsp_sink.h"
#include "rtsp_common.h"
#include "raw_parser.h"

namespace flvpusher {

class SubstreamDescriptor {
public:
    SubstreamDescriptor(MultiFramedRTPSink *rtp_sink, unsigned track_id);
    ~SubstreamDescriptor();

    MultiFramedRTPSink *rtp_sink() const { return m_rtp_sink; }
    char const *sdp_lines() const { return m_sdp_lines; }

private:
    MultiFramedRTPSink *m_rtp_sink;
    char *m_sdp_lines;
};

/////////////////////////////////////////////////////////////

RtspSink::RtspSink(const std::string &flvpath) :
    MediaSink(flvpath),
    m_proc_thrd(NULL),
    m_substream_sdp_sizes(0),
    m_last_track_id(0),
    m_video_sink(NULL), m_audio_sink(NULL)
{
    m_client = new RtspClient(NULL);
}

RtspSink::~RtspSink()
{
    JOIN_DELETE_THREAD(m_proc_thrd);

    Frame *f;
    m_vqueue.cancel_wait();
    m_aqueue.cancel_wait();
    while (!m_vqueue.pop(f)) { SAFE_DELETE(f); }
    while (!m_aqueue.pop(f)) { SAFE_DELETE(f); }

    SAFE_DELETE(m_video_sink); SAFE_DELETE(m_audio_sink);
    SAFE_DELETE(m_client);

    FOR_VECTOR_ITERATOR(SubstreamDescriptor *, m_substream_descriptors, it) {
        SAFE_DELETE(*it);
    }
}

MediaSink::Type RtspSink::type() const
{
    return RTSP_SINK;
}

int RtspSink::connect(const std::string &liveurl)
{
    m_our_ap = AddressPort(our_ip(), 0);
    if (m_client->open(liveurl, m_our_ap) < 0)
        return -1;

    if (m_client->request_options(
                (TaskFunc *) RtspClient::continue_after_option) < 0) {
        LOGE("Failed to send OPTION command");
        return -1;
    }

    m_liveurl = liveurl;
    m_proc_thrd = CREATE_THREAD_ROUTINE(proc_routine, NULL, false);
    return 0;
}

void *RtspSink::proc_routine(void *arg)
{
    m_client->loop(&m_quit);
    return (void *) NULL;
}

int RtspSink::disconnect()
{
    return 0;
}

int RtspSink::send_video(int32_t timestamp, byte *dat, uint32_t length)
{
    AutoLock _l(m_mutex);

    Frame *f = new Frame;
    f->make_frame(timestamp, dat, length, false);

    if (!m_video_sink) {
        VideoRawParser vparser;
        if (!vparser.process(dat, length) &&
            vparser.is_key_frame() &&
            vparser.get_sps_length() && vparser.get_pps_length()) {
            m_video_sink = new H264VideoRTPSink(NULL, 96,
                                                vparser.get_sps(), vparser.get_sps_length(),
                                                vparser.get_pps(), vparser.get_pps_length());
            add_stream(m_video_sink);
            if (check_and_set_destination() < 0) {
                return -1;
            }
        }
    }

    return m_vqueue.push(f);
}

int RtspSink::send_audio(int32_t timestamp, byte *dat, uint32_t length)
{
    AutoLock _l(m_mutex);

    if (!m_audio_sink) {
        AudioRawParser aparser;
        if (!aparser.process(dat, length)) {
            byte asc[2];
            memcpy(asc, aparser.get_asc(), 2);
            uint8_t profile, sample_rate_idx, channel;
            parse_asc(asc, 2, profile, sample_rate_idx, channel);
            m_audio_sink = new MPEG4GenericRTPSink(NULL, 97, atoi(samplerate_idx_to_str(sample_rate_idx)),
                                                   "audio", "AAC-hbr",
                                                   STR(sprintf_("%02X%02X", asc[0], asc[1])), channel);
            add_stream(m_audio_sink);
            if (check_and_set_destination() < 0) {
                return -1;
            }
        }
    }

    Frame *f = new Frame;
    f->make_frame(timestamp, dat, length, false);
    return m_aqueue.push(f);
}

void RtspSink::add_stream(MultiFramedRTPSink *rtp_sink)
{
    if (!rtp_sink) return;

    SubstreamDescriptor *new_descriptor = new SubstreamDescriptor(rtp_sink, m_last_track_id++);
    m_substream_descriptors.push_back(new_descriptor);
    m_substream_sdp_sizes += strlen(new_descriptor->sdp_lines());
}

int RtspSink::check_and_set_destination()
{
    if (!m_video_sink || !m_audio_sink) {
        return 0;
    }

    std::auto_ptr<xuri::Uri> uri_parser(new xuri::Uri);
    uri_parser->parse(STR(m_liveurl));

    unsigned const sdp_session_id = random32();
    unsigned const sdp_version = sdp_session_id;
    std::string sdp = sprintf_("v=0"CRLF
                               "o=- %u %u IN IP4 %s"CRLF
                               "s=flvpusher"CRLF
                               "i=flvpusher"CRLF
                               "c=IN IP4 %s"CRLF
                               "t=0 0"CRLF
                               "a=x-qt-text-nam:"CRLF
                               "a=x-qt-text-inf:"CRLF
                               "a=x-qt-text-cmt:source application:flvpusher"CRLF
                               "a=x-qt-text-aut:"CRLF
                               "a=x-qt-text-cpy:"CRLF,
                               sdp_session_id, sdp_version, m_our_ap.get_address(),
                               uri_parser->host);
    FOR_VECTOR_ITERATOR(SubstreamDescriptor *, m_substream_descriptors, it) {
        sdp += (*it)->sdp_lines();
    }

    if (m_client->request_announce(sdp) < 0) {
        LOGE("Failed to send ANNOUNCE command");
        return -1;
    }

    return 0;
}

/////////////////////////////////////////////////////////////

SubstreamDescriptor::SubstreamDescriptor(MultiFramedRTPSink *rtp_sink, unsigned track_id) :
    m_rtp_sink(rtp_sink)
{
    char *rtpmap_line = m_rtp_sink->rtpmap_line();
    char const *aux_sdp_line = m_rtp_sink->aux_sdp_line();
    if (!aux_sdp_line) aux_sdp_line = "";

    m_sdp_lines = strdup_(STR(sprintf_("m=%s 0 RTP/AVP %u"CRLF
                                       "%s"
                                       "%s"
                                       "a=control:trackID=%u"CRLF,
                                       m_rtp_sink->sdp_media_type(), m_rtp_sink->rtp_payload_type(),
                                       rtpmap_line,
                                       aux_sdp_line,
                                       track_id)));
    SAFE_FREE(rtpmap_line);
}

SubstreamDescriptor::~SubstreamDescriptor()
{
    SAFE_FREE(m_sdp_lines);
}

}
