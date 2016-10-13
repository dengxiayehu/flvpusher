#include "mp4_pusher1.h"

#include <amf.h>
#include <xlog.h>

#include "mp4_parser.h"
#include "common/media_sink.h"
#include "rtmp/rtmp_sink.h"

using namespace amf;

namespace flvpusher {

MP4Pusher1::MP4Pusher1(const std::string &input, MediaSink *&sink) :
  MediaPusher(input, sink),
  m_parser(NULL),
  m_width(0), m_height(0)
{
}

MP4Pusher1::~MP4Pusher1()
{
  SAFE_DELETE(m_parser);
}

int MP4Pusher1::prepare()
{
  m_parser = new MP4Parser;
  if (m_parser->set_file(STR(m_input)) < 0) {
    LOGE("Load file \"%s\" failed", STR(m_input));
    return -1;
  }

  if (m_parser->get_resolution(m_width, m_height) < 0) {
    LOGE("Get file's resolution failed");
    return -1;
  }
  if (m_sink->type() == MediaSink::RTMP_SINK &&
      !send_metadata()) {
    LOGE("Send metadata to %sserver failed (cont)",
         STR(m_sink->type_str()));
  }

  if (!m_tspath.empty())
    set_itime_base(m_parser->get_vtime_base());
  return 0;
}

int MP4Pusher1::loop()
{
  if (prepare() < 0) {
    LOGE("MP4Pusher1's prepare() failed");
    return -1;
  }

  LOGI("Pushing file \"%s\" ..", STR(m_input));

  return m_parser->process(this, parsed_frame_cb);
}

int MP4Pusher1::parsed_frame_cb(void *opaque, Frame *f, int is_video)
{
  MP4Pusher1 *obj = (MP4Pusher1 *) opaque;
  int ret = 0;
  int dts = f->get_dts();

  if (obj->frame_wait_done(&dts) < 0)
    return -1;

  obj->on_frame(dts, f->get_data(), f->get_data_length(), is_video,
                f->get_composition_time());

  if (is_video) {
    if (obj->m_sink->send_video(dts,
                                f->get_data(), f->get_data_length(),
                                f->get_composition_time()) < 0) {
      LOGE("Send video data to %sserver failed",
           STR(obj->m_sink->type_str()));
      ret = -1;
    }
  } else {
    if (obj->m_sink->send_audio(dts,
                                f->get_data(), f->get_data_length()) < 0) {
      LOGE("Send audio data to %sserver failed",
           STR(obj->m_sink->type_str()));
      ret = -1;
    }
  }

  return ret;
}

int MP4Pusher1::send_metadata()
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
