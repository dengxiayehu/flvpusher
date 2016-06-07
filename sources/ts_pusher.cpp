#include "ts_pusher.h"

#include <xutil.h>
#include <xlog.h>
#include <amf.h>
#include <ffmpeg.h>

#include "ts_parser.h"
#include "rtmp_handler.h"

using namespace xutil;
using namespace amf;

namespace flvpusher {

TSPusher::TSPusher(const std::string &input, RtmpHandler *&rtmp_hdl) :
    MediaPusher(input, rtmp_hdl),
    m_parser(NULL),
    m_prev_ts(-1), m_tm_start(UINT64_MAX),
    m_width(0), m_height(0)
{
}

TSPusher::~TSPusher()
{
    SAFE_DELETE(m_parser);
}

int TSPusher::prepare()
{
    m_parser = new TSParser;
    if (m_parser->set_file(STR(m_input)) < 0) {
        LOGE("Load ts file \"%s\" failed", STR(m_input));
        return -1;
    }

    if (m_parser->get_resolution(m_width, m_height) < 0) {
        LOGE("Get file's resolution failed");
        return -1;
    }
    if (!send_metadata()) {
        LOGE("Send metadata to rtmpserver failed (cont)");
    }

    return 0;
}

int TSPusher::loop()
{
    if (prepare() < 0) {
        LOGE("TSPusher's prepare() failed");
        return -1;
    }
    
    LOGI("Pushing ts file \"%s\" ..", STR(m_input));

    return m_parser->process(this, parsed_frame_cb);
}

void TSPusher::ask2quit()
{
    if (m_parser)
        m_parser->ask2quit(); // In case it gets stuck in format_find_stream_info()
    m_quit = true;
}

int TSPusher::parsed_frame_cb(void *opaque, Frame *f, int is_video)
{
    TSPusher *obj = (TSPusher *) opaque;
    int ret = 0;

    if (obj->m_prev_ts == -1)
        obj->m_prev_ts = f->m_ts;
    if (obj->m_tm_start == UINT64_MAX)
        obj->m_tm_start = get_time_now();

    obj->on_frame(f->m_ts, f->m_dat, f->m_dat_len, is_video);

    if (f->m_ts > obj->m_prev_ts) {
        int32_t adjust_tm = get_time_now() - obj->m_tm_start - obj->m_prev_ts;

        if (f->m_ts - obj->m_prev_ts > adjust_tm)
            usleep((f->m_ts - obj->m_prev_ts - adjust_tm)*1000);

        obj->m_prev_ts = f->m_ts;
    }

    if (is_video) {
        if (obj->m_rtmp_hdl->send_video(f->m_ts,
                                        f->m_dat, f->m_dat_len) < 0) {
            LOGE("Send video data to rtmpserver failed");
            ret = -1;
        }
    } else {
        if (obj->m_rtmp_hdl->send_audio(f->m_ts,
                                        f->m_dat, f->m_dat_len) < 0) {
            LOGE("Send audio data to rtmpserver failed");
            ret = -1;
        }
    }

    return ret;
}

int TSPusher::send_metadata()
{
    byte buff[1024], *p = buff;
    put_amf_string(p, "onMetaData");
    put_byte(p, AMF_TYPE_OBJECT);
    put_amf_string_no_typ(p, "width");
    put_amf_number(p, m_width);
    put_amf_string_no_typ(p, "height");
    put_amf_number(p, m_height);
    put_amf_obj_end(p);
    return m_rtmp_hdl->send_rtmp_pkt(RTMP_PACKET_TYPE_INFO, 0 /* metadata's timestamp is always 0*/,
                                     buff, p - buff);
}

}
