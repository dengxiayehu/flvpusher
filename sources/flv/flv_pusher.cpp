#include <xutil.h>
#include <xlog.h>

#include "flv_pusher.h"
#include "flv_parser.h"
#include "tag_streamer.h"
#include "common/media_sink.h"
#include "rtmp/rtmp_sink.h"

using namespace xutil;
using namespace xmedia;

namespace flvpusher {

FLVPusher::FLVPusher(const std::string &input, MediaSink *&sink) :
    MediaPusher(input, sink)
{
    m_vstrmer = new VideoTagStreamer();
    m_astrmer = new AudioTagStreamer();
    m_sstrmer = new ScriptTagStreamer();
}

FLVPusher::~FLVPusher()
{
    SAFE_DELETE(m_vstrmer);
    SAFE_DELETE(m_astrmer);
    SAFE_DELETE(m_sstrmer);
}

int FLVPusher::loop()
{
    FLVParser parser;
    if (parser.set_file(STR(m_input)) < 0) {
        LOGE("Load flv file \"%s\" failed", STR(m_input));
        return -1;
    }

    LOGI("Pushing flv file \"%s\" ..", STR(m_input));

    uint64_t tm_start = get_time_now();
    int32_t prev_ts = 0;

    while (!parser.eof() && !m_quit) {
        FLVParser::FLVTag *tag = parser.alloc_tag();
        if (parser.read_tag(tag) < 0) {
            if (tag->hdr.typ == FLVParser::TAG_SCRIPT) {
                parser.free_tag(tag);
                continue;
            }

            parser.free_tag(tag);
            break;
        }

        int32_t timestamp =
            (tag->hdr.timestamp_ext<<24) + VALUI24(tag->hdr.timestamp);
        // Need to sleep a while to meet the timestamp of media data
        if (timestamp > prev_ts) {
            int32_t adjust_tm = get_time_now() - tm_start - prev_ts;

            if (timestamp - prev_ts > adjust_tm)
                usleep((timestamp - prev_ts - adjust_tm)*1000);

            prev_ts = timestamp;
        }

        if (m_quit) {
            parser.free_tag(tag);
            break;
        }

        switch (tag->hdr.typ) {
            case FLVParser::TAG_VIDEO:
                m_vstrmer->process(*tag);
                if (m_vstrmer->get_strm_length() == 0)
                    break;
                on_frame(timestamp,
                         m_vstrmer->get_strm(), m_vstrmer->get_strm_length(), 1);
                if (m_sink->send_video(timestamp,
                                       m_vstrmer->get_strm(), m_vstrmer->get_strm_length()) < 0) {
                    LOGE("Send video data to rtmpserver failed");
                    m_quit = true;
                }
                break;

            case FLVParser::TAG_AUDIO:
                m_astrmer->process(*tag);
                if (m_astrmer->get_strm_length() == 0)
                    break;
                on_frame(timestamp,
                         m_astrmer->get_strm(), m_astrmer->get_strm_length(), 0);
                if (m_sink->send_audio(timestamp,
                                       m_astrmer->get_strm(), m_astrmer->get_strm_length()) < 0) {
                    LOGE("Send audio data to rtmpserver failed");
                    m_quit = true;
                }
                break;

            case FLVParser::TAG_SCRIPT:
                m_sstrmer->process(*tag);
                if (m_sink->type() == MediaSink::RTMP_SINK &&
                    !((RtmpSink *) m_sink)->send_rtmp_pkt(RTMP_PACKET_TYPE_INFO, 0,
                                                          m_sstrmer->get_strm(), m_sstrmer->get_strm_length())) {
                    LOGE("Send metadata to rtmpserver failed (cont)");
                }
                break;

            default:
                break;
        }

        parser.free_tag(tag);
    }

    return 0;
}

}
