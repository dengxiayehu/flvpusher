#include "mp4_pusher.h"
#include "mp4_parser.h"
#include "common/media_sink.h"
#include "rtmp/rtmp_sink.h"

#include <xlog.h>
#include <amf.h>

using namespace amf;

namespace flvpusher {

MP4Pusher::MP4Pusher(const std::string &input, MediaSink *&sink) :
    MediaPusher(input, sink),
    m_vthrd(NULL), m_athrd(NULL),
    m_parser(NULL),
    m_tm_start(0),
    m_retval(0)
{
}

MP4Pusher::~MP4Pusher()
{
    SAFE_DELETE(m_parser);
}

int MP4Pusher::prepare()
{
    m_parser = new MP4Parser;
    if (m_parser->set_file(STR(m_input)) < 0) {
        LOGE("Load file \"%s\" failed", STR(m_input));
        return -1;
    }

    if (!m_tspath.empty())
        set_itime_base(m_parser->get_vtime_base());

    // Start time of this push, video&audio timestamp will reference it
    m_tm_start = get_time_now();

    m_vthrd = CREATE_THREAD_ROUTINE(vsnd_func, NULL, false);
    m_athrd = CREATE_THREAD_ROUTINE(asnd_func, NULL, false);
    return 0;
}

int MP4Pusher::loop()
{
    if (prepare() < 0) {
        LOGE("MP4Pusher's prepare() failed");
        return -1;
    }
    
    LOGI("Pushing file \"%s\" ..", STR(m_input));

    // Send metadata pkt to mediaserver
    if (m_sink->type() == MediaSink::RTMP_SINK &&
        !send_metadata()) {
        LOGE("Send metadata to %sserver failed (cont)",
             STR(m_sink->type_str()));
    }

    /* Media-data send-thread is working .. */

    JOIN_DELETE_THREAD(m_vthrd);
    JOIN_DELETE_THREAD(m_athrd);

    return m_retval;
}

int MP4Pusher::send_metadata()
{
    const MP4Parser::Track *vtrak =
        m_parser->get_track(MP4Parser::VIDEO);

    byte buff[1024], *p = buff;
    put_amf_string(p, "onMetaData");
    put_byte(p, AMF_TYPE_OBJECT);
    put_amf_string_no_typ(p, "width");
    put_amf_number(p, vtrak->avc1->width);
    put_amf_string_no_typ(p, "height");
    put_amf_number(p, vtrak->avc1->height);
    put_amf_obj_end(p);
    return ((RtmpSink *) m_sink)->send_rtmp_pkt(RTMP_PACKET_TYPE_INFO, 0 /* metadata's timestamp is always 0*/,
                                                buff, p - buff);
}

void *MP4Pusher::vsnd_func(void *arg)
{
    Frame frame;
    int32_t prev_ts = 0; // In milliseconds
    while (!m_quit) {
        {
            AutoLock _l(m_mutex);
            if (m_parser->read_vframe(&frame) < 0) {
                break;
            }
        }

        on_frame(frame.m_ts, frame.m_dat, frame.m_dat_len, 1);

        if (frame.m_ts > prev_ts) {
            // Need to sleep a while to meet the timestamp of frame
            int32_t adjust_tm = (get_time_now() - m_tm_start) - prev_ts;

            if (frame.m_ts - prev_ts > adjust_tm)
                usleep((frame.m_ts - prev_ts - adjust_tm)*1000);
            else
                usleep(0); // Yield the processcor

            prev_ts = frame.m_ts;
        }

        {
            AutoLock _l(m_mutex);
            if (m_sink->send_video(frame.m_ts, frame.m_dat, frame.m_dat_len) < 0) {
                m_quit = true;
                m_retval = -1;
                break;
            }
        }

        frame.clear();
    }

    return NULL;
}

void *MP4Pusher::asnd_func(void *arg)
{
    Frame frame;
    int32_t prev_ts = 0; // In milliseconds
    while (!m_quit) {
        {
            AutoLock _l(m_mutex);
            if (m_parser->read_aframe(&frame) < 0) {
                break;
            }
        }

        on_frame(frame.m_ts, frame.m_dat, frame.m_dat_len, 0);

        if (frame.m_ts > prev_ts) {
            int32_t adjust_tm = (get_time_now() - m_tm_start) - prev_ts;

            if (frame.m_ts - prev_ts > adjust_tm)
                usleep((frame.m_ts - prev_ts - adjust_tm)*1000);
            else
                usleep(0); // Yield the processcor

            prev_ts = frame.m_ts;
        }

        {
            AutoLock _l(m_mutex);
            if (m_sink->send_audio(frame.m_ts, frame.m_dat, frame.m_dat_len) < 0) {
                m_quit = true;
                m_retval = -1;
                break;
            }
        }

        frame.clear();
    }

    return NULL;
}

}
