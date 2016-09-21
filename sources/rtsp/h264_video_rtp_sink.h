#ifndef _H264_VIDEO_RTP_SINK_H_
#define _H264_VIDEO_RTP_SINK_H_

#include "multi_framed_rtp_sink.h"

namespace flvpusher {

class H264Fragmenter;

class H264VideoRTPSink : public MultiFramedRTPSink {
public:
  H264VideoRTPSink(TaskScheduler *scheduler, RtpInterface *interface, unsigned char rtp_payload_format,
                   uint8_t const *sps = NULL, unsigned sps_size = 0,
                   uint8_t const *pps = NULL, unsigned pps_size = 0);
  virtual ~H264VideoRTPSink();

  virtual char const *sdp_media_type() const;
  virtual char const *aux_sdp_line();

private:
  virtual bool continue_playing();
  virtual void do_special_frame_handling(unsigned fragmentation_offset,
                                         unsigned char *frame_start,
                                         unsigned num_bytes_in_frame,
                                         struct timeval frame_presentation_time,
                                         unsigned num_remaining_bytes);
  virtual bool frame_can_appear_after_packet_start(unsigned char const *frame_start,
                                                   unsigned num_bytes_in_frame) const;

private:
  DISALLOW_COPY_AND_ASSIGN(H264VideoRTPSink);
  H264Fragmenter *m_our_fragmenter;
  char *m_fmtp_sdp_line;
  uint8_t *m_sps; unsigned m_sps_size;
  uint8_t *m_pps; unsigned m_pps_size;
};

}

#endif /* end of _H264_VIDEO_RTP_SINK_H_ */
