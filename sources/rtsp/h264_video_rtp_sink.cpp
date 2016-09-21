#include <xutil.h>

#include "rtsp_common.h"
#include "h264_video_rtp_sink.h"
#include "h264_fragmenter.h"
#include "out_packet_buffer.h"

using namespace xutil;

namespace flvpusher {

H264VideoRTPSink::H264VideoRTPSink(TaskScheduler *scheduler,
                                   RtpInterface *interface, unsigned char rtp_payload_format,
                                   uint8_t const *sps, unsigned sps_size,
                                   uint8_t const *pps, unsigned pps_size) :
  MultiFramedRTPSink(scheduler, interface, rtp_payload_format, 90000, "H264"),
  m_our_fragmenter(NULL), m_fmtp_sdp_line(NULL)
{
  if (sps) {
    m_sps_size = sps_size;
    m_sps = new uint8_t[m_sps_size];
    memmove(m_sps, sps, m_sps_size);
  } else {
    m_sps = NULL;
    m_sps_size = 0;
  }
  if (pps) {
    m_pps_size = pps_size;
    m_pps = new uint8_t[m_pps_size];
    memmove(m_pps, pps, m_pps_size);
  } else {
    m_pps = NULL;
    m_pps_size = 0;
  }
}

H264VideoRTPSink::~H264VideoRTPSink()
{
  SAFE_FREE(m_fmtp_sdp_line);
  SAFE_DELETE_ARRAY(m_sps); SAFE_DELETE_ARRAY(m_pps);
  SAFE_DELETE(m_our_fragmenter);
}

char const *H264VideoRTPSink::sdp_media_type() const
{
  return "video";
}

char const *H264VideoRTPSink::aux_sdp_line()
{
  if (!m_sps || !m_pps) {
    LOGW("Unknown sps and/or pps in H264VideoRTPSink");
    return NULL;
  }

  uint32_t profile_level_id = (m_sps[1]<<16) | (m_sps[2]<<8) | m_sps[3];
  char *sps_base64 = base64_encode((char *) m_sps, m_sps_size);
  char *pps_base64 = base64_encode((char *) m_pps, m_pps_size);

  SAFE_FREE(m_fmtp_sdp_line);
  m_fmtp_sdp_line = strdup_(STR(sprintf_(
          "a=fmtp:%d packetization-mode=1;profile-level-id=%06X;sprop-parameter-sets=%s,%s"CRLF,
          rtp_payload_type(), profile_level_id, sps_base64, pps_base64)));

  SAFE_FREE(sps_base64);
  SAFE_FREE(pps_base64);

  return m_fmtp_sdp_line;
}

bool H264VideoRTPSink::continue_playing()
{
  if (!m_our_fragmenter) {
    m_our_fragmenter = new H264Fragmenter(m_queue_src,
                                          OutPacketBuffer::max_size, our_max_packet_size() - rtp_header_size);
  }
  m_queue_src = (xutil::Queue<xmedia::Frame *> *) m_our_fragmenter;

  return MultiFramedRTPSink::continue_playing();
}

void H264VideoRTPSink::do_special_frame_handling(unsigned fragmentation_offset,
                                                 unsigned char *frame_start,
                                                 unsigned num_bytes_in_frame,
                                                 struct timeval frame_presentation_time,
                                                 unsigned num_remaining_bytes)
{
  // Set the RTP 'M' (marker) bit if
  // 1/ The most recently delivered fragment was the end of (or the only fragment of) an NAL unit, and
  // 2/ This NAL unit was the last NAL unit of an 'access unit' (i.e. video frame).
  if (m_our_fragmenter) {
    if (m_our_fragmenter->last_fragment_completed_nal_unit() &&
        m_our_fragmenter->picture_end_marker()) {
      set_marker_bit();
    }
  }

  set_timestamp(frame_presentation_time);
}

bool H264VideoRTPSink::frame_can_appear_after_packet_start(unsigned char const *frame_start,
                                                           unsigned num_bytes_in_frame) const
{
  return false;
}

}
