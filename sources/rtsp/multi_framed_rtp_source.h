#ifndef _MULTI_FRAMED_RTP_SOURCE_H_
#define _MULTI_FRAMED_RTP_SOURCE_H_

#include <xutil.h>
#include <ffmpeg.h>

#include "rtp_receiver.h"

namespace flvpusher {

class TaskScheduler;
class RtpInterface;

class MultiFramedRTPSource {
public:
  MultiFramedRTPSource(TaskScheduler *scheduler, RtpInterface *interface, unsigned char rtp_payload_format,
                       unsigned rtp_timestamp_frequency, void *opaque = NULL);
  virtual ~MultiFramedRTPSource();

  int start_receiving();

  virtual int set_dump_filename(const std::string &filename)
  { return m_file.open(STR(filename), "wb") ? 0 : -1; }

protected:
  virtual bool process_special_header(uint8_t *payload, unsigned payload_len,
                                      bool marker_bit, unsigned &result_special_header_size) = 0;
  virtual const char *MIME_type() const = 0;
  virtual const unsigned next_enclosed_frame_size(unsigned data_size) { return data_size; }
  virtual const ffmpeg::CodecID codec_id() const = 0;
  virtual int on_complete_frame1(FrameBuffer *frame) = 0;

private:
  static void network_read_handler(MultiFramedRTPSource *source, int mask);
  void network_read_handler1(int mask);

  static int on_complete_frame(MultiFramedRTPSource *source, FrameBuffer *frame);

  enum {INITIAL_TIMESTAMP_OFFSET = 1989};

protected:
  TaskScheduler *m_scheduler;
  RtpInterface *m_interface;
  unsigned char m_rtp_payload_format;
  unsigned m_rtp_timestamp_frequency;
  bool m_are_doing_network_reads;
  Receiver m_receiver;
  uint32_t m_ssrc;
  bool m_current_packet_begins_frame;
  bool m_current_packet_completes_frame;
  bool m_received_pkt;
  uint16_t m_last_received_seq_num;
  uint32_t m_last_received_timestamp;
  xutil::MemHolder m_mem_holder;
  xfile::File m_file;
  uint32_t m_start_complete_timestamp;
  void *m_opaque;
};

}

#endif /* end of _MULTI_FRAMED_RTP_SOURCE_H_ */
