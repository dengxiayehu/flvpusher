#include "mpeg4_generic_rtp_sink.h"
#include "rtsp_common.h"
#include "rtp_interface.h"

using namespace xutil;

namespace flvpusher {

MPEG4GenericRTPSink::MPEG4GenericRTPSink(TaskScheduler *scheduler,
                                         RtpInterface *interface, unsigned char rtp_payload_format,
                                         uint32_t rtp_timestamp_frequency,
                                         char const *sdp_media_type_string,
                                         char const *mpeg4_mode, char const *config_string,
                                         unsigned num_channels) :
  MultiFramedRTPSink(scheduler, interface, rtp_payload_format,
                     rtp_timestamp_frequency, "MPEG4-GENERIC", num_channels),
  m_sdp_media_type_string(strdup_(sdp_media_type_string)),
  m_mpeg4_mode(strdup_(mpeg4_mode)),
  m_config_string(strdup_(config_string))
{
  if (strcasecmp(mpeg4_mode, "aac-hbr") != 0) {
    LOGE("Unknown \"mpeg4_mode\" parameter: %s",
         mpeg4_mode);
  }

  m_fmtp_sdp_line = strdup_(STR(sprintf_(
          "a=fmtp:%d streamtype=5;profile-level-id=1;mode=%s;sizelength=13;indexlength=3;indexdeltalength=3;config=%s"CRLF,
          rtp_payload_type(), m_mpeg4_mode, m_config_string)));
}

MPEG4GenericRTPSink::~MPEG4GenericRTPSink()
{
  free((char *) m_sdp_media_type_string);
  free((char *) m_mpeg4_mode);
  free((char *) m_config_string);
  SAFE_FREE(m_fmtp_sdp_line);
}

char const *MPEG4GenericRTPSink::sdp_media_type() const
{
  return m_sdp_media_type_string;
}

char const *MPEG4GenericRTPSink::aux_sdp_line()
{
  return m_fmtp_sdp_line;
}

bool MPEG4GenericRTPSink::frame_can_appear_after_packet_start(unsigned char const *frame_start,
    unsigned num_bytes_in_frame) const
{
  // (For now) allow at most 1 frame in a single packet:
  return false;
}

unsigned MPEG4GenericRTPSink::special_header_size() const
{
  return 2 + 2;
}

void MPEG4GenericRTPSink::do_special_frame_handling(unsigned fragmentation_offset,
                                                    unsigned char *frame_start,
                                                    unsigned num_bytes_in_frame,
                                                    struct timeval frame_presentation_time,
                                                    unsigned num_remaining_bytes)
{
  unsigned full_frame_size
    = fragmentation_offset + num_bytes_in_frame + num_remaining_bytes;
  unsigned char headers[4];
  headers[0] = 0; headers[1] = 16; /* bits AU-headers-length*/
  headers[2] = full_frame_size >> 5; headers[3] = (full_frame_size&0x1F)<<3;

  set_special_header_bytes(headers, sizeof(headers));

  if (num_remaining_bytes == 0) {
    // This packet contains the last (or only) fragment of the frame.
    // Set the RTP 'M' ('marker') bit:
    set_marker_bit();
  }

  // Important: Also call our base class's do_special_frame_handling(),
  // to set the packet's timestamp:
  MultiFramedRTPSink::do_special_frame_handling(fragmentation_offset,
                                                frame_start,
                                                num_bytes_in_frame,
                                                frame_presentation_time,
                                                num_remaining_bytes);
}

}
