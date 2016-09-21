#ifndef _MPEG4_GENERIC_RTP_SINK_H_
#define _MPEG4_GENERIC_RTP_SINK_H_

#include "multi_framed_rtp_sink.h"

namespace flvpusher {

class TaskScheduler;
class RtpInterface;

class MPEG4GenericRTPSink : public MultiFramedRTPSink {
public:
  MPEG4GenericRTPSink(TaskScheduler *scheduler, RtpInterface *interface, unsigned char rtp_payload_format,
                      uint32_t rtp_timestamp_frequency,
                      char const *sdp_media_type_string,
                      char const *mpeg4_mode, char const *config_string,
                      unsigned num_channels);
  virtual ~MPEG4GenericRTPSink();

  virtual char const *sdp_media_type() const;
  virtual char const *aux_sdp_line();

  char const *config_string() const { return m_config_string; }

private:
  virtual bool frame_can_appear_after_packet_start(unsigned char const *frame_start,
                                                   unsigned num_bytes_in_frame) const;
  virtual void do_special_frame_handling(unsigned fragmentation_offset,
                                         unsigned char *frame_start,
                                         unsigned num_bytes_in_frame,
                                         struct timeval frame_presentation_time,
                                         unsigned num_remaining_bytes);
  virtual unsigned special_header_size() const;

private:
  char const *m_sdp_media_type_string;
  char const *m_mpeg4_mode;
  char const *m_config_string;
  char *m_fmtp_sdp_line;
};

}

#endif /* end of _MPEG4_GENERIC_RTP_SINK_H_ */
