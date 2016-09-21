#ifndef _MPEG4_GENERIC_RTP_SOURCE_H_
#define _MPEG4_GENERIC_RTP_SOURCE_H_

#include "multi_framed_rtp_source.h"

namespace flvpusher {

class MPEG4GenericRTPSource : public MultiFramedRTPSource {
public:
  MPEG4GenericRTPSource(TaskScheduler *scheduler, RtpInterface *interface,
                        unsigned char rtp_payload_format,
                        unsigned rtp_timestamp_frequency,
                        const char *medium_name,
                        const char *mode,
                        unsigned size_length, unsigned index_length,
                        unsigned index_delta_length,
                        const char *fmtp_config,
                        void *opaque = NULL);
  virtual ~MPEG4GenericRTPSource();

protected:
  virtual bool process_special_header(uint8_t *payload, unsigned payload_len,
                                      bool marker_bit, unsigned &result_special_header_size);
  virtual const char *MIME_type() const { return m_MIME_type; }
  virtual const unsigned next_enclosed_frame_size(unsigned data_size);
  virtual const ffmpeg::CodecID codec_id() const { return ffmpeg::CODEC_ID_AAC; }
  virtual int on_complete_frame1(FrameBuffer *frame);

private:
  unsigned m_size_length;
  unsigned m_index_length;
  unsigned m_index_delta_length;
  char *m_MIME_type;
  unsigned m_num_au_headers;
  unsigned m_next_au_header;
  struct AUHeader {
    unsigned size;
    unsigned index;
  } *m_au_headers;
  char *m_fmtp_config;
};

}

#endif /* end of _MPEG4_GENERIC_RTP_SOURCE_H_ */
