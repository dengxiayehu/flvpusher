#include <xutil.h>
#include <xlog.h>
#include <amf.h>
#include <ffmpeg.h>

#include "ts_pusher.h"
#include "ts_parser.h"
#include "common/media_sink.h"
#include "rtmp/rtmp_sink.h"

using namespace xutil;
using namespace amf;

namespace flvpusher {

TSPusher::TSPusher(const std::string &input, MediaSink *&sink, bool hls_segment) :
  MediaPusher(input, sink),
  m_parser(NULL),
  m_prev_ts(-1), m_tm_start(UINT64_MAX), m_tm_offset(0),
  m_width(0), m_height(0),
  m_hls_segment(hls_segment)
{
}

TSPusher::~TSPusher()
{
  SAFE_DELETE(m_parser);
}

int TSPusher::init_parser()
{
  if (!m_parser) {
    m_parser = new TSParser;
    if (m_parser->set_file(STR(m_input), m_hls_segment) < 0) {
      LOGE("Load ts file \"%s\" failed", STR(m_input));
      return -1;
    }

    if (m_parser->get_resolution(m_width, m_height) < 0) {
      LOGE("Get file's resolution failed");
      return -1;
    }
  }
  return 0;
}

TSParser *TSPusher::get_parser() const
{
  return m_parser;
}

void TSPusher::set_timestamp_offset(int tm_offset)
{
  m_tm_offset = tm_offset;
}

int TSPusher::prepare()
{
  if (init_parser() < 0) {
    return -1;
  }

  if (m_sink->type() == MediaSink::RTMP_SINK &&
      !send_metadata()) {
    LOGE("Send metadata to %sserver failed (cont)",
         STR(m_sink->type_str()));
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

  f->m_ts += obj->m_tm_offset;

  if (obj->m_prev_ts == -1) {
    obj->m_prev_ts = f->m_ts;
  }

  if (obj->m_tm_start == UINT64_MAX) {
    obj->m_tm_start = get_time_now() - f->m_ts;
  }

  obj->on_frame(f->m_ts, f->m_dat, f->m_dat_len, is_video);

  if (f->m_ts > obj->m_prev_ts) {
    int32_t adjust_tm = get_time_now() - obj->m_tm_start - obj->m_prev_ts;

    if (f->m_ts - obj->m_prev_ts > adjust_tm) {
      sleep_(f->m_ts - obj->m_prev_ts - adjust_tm);
    }

    obj->m_prev_ts = f->m_ts;
  }

  if (is_video) {
    if (obj->m_sink->send_video(f->m_ts,
          f->m_dat, f->m_dat_len) < 0) {
      LOGE("Send video data to %sserver failed",
           STR(obj->m_sink->type_str()));
      ret = -1;
    }
  } else {
    if (obj->m_sink->send_audio(f->m_ts,
          f->m_dat, f->m_dat_len) < 0) {
      LOGE("Send video data to %sserver failed",
           STR(obj->m_sink->type_str()));
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
  return ((RtmpSink *) m_sink)->send_rtmp_pkt(RTMP_PACKET_TYPE_INFO, 0 /* metadata's timestamp is always 0*/,
                                              buff, p - buff);
}

}
