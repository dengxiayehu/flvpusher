#ifndef _H264_VIDEO_RTP_SOURCE_H_
#define _H264_VIDEO_RTP_SOURCE_H_

#include <ffmpeg.h>

#include "multi_framed_rtp_source.h"

namespace flvpusher {

class SPropRecord {
public:
  SPropRecord() : m_s_prop_bytes(NULL) { }
  ~SPropRecord() { SAFE_FREE(m_s_prop_bytes); }

  unsigned &s_prop_length() { return m_s_prop_length; }
  unsigned char *&s_prop_bytes() { return m_s_prop_bytes; }

private:
  unsigned m_s_prop_length;
  unsigned char *m_s_prop_bytes;
};

SPropRecord *parse_s_prop_parm_str(const char *parm_str, unsigned &num_s_prop_records);

class TaskScheduler;
class RtpInterface;

class H264VideoRTPSource : public MultiFramedRTPSource {
public:
  H264VideoRTPSource(TaskScheduler *scheduler, RtpInterface *interface, unsigned char rtp_payload_format,
                     unsigned rtp_timestamp_frequency, const char *s_prop_parm_str = NULL,
                     void *opaque = NULL);
  virtual ~H264VideoRTPSource();

protected:
  virtual bool process_special_header(uint8_t *payload, unsigned payload_len,
                                      bool marker_bit, unsigned &result_special_header_size);
  virtual const char *MIME_type() const { return "video/H264"; }
  virtual const ffmpeg::CodecID codec_id() const { return ffmpeg::CODEC_ID_H264; }
  virtual int on_complete_frame1(FrameBuffer *frame);

private:
  unsigned char m_cur_pkt_NALU_type;
  unsigned char *m_sps;
  unsigned m_sps_size;
  unsigned char *m_pps;
  unsigned m_pps_size;
};

}

#endif /* end of _H264_VIDEO_RTP_SOURCE_H_ */
