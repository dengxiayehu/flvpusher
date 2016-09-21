#ifndef _MULTI_FRAMED_RTP_SINK_H_
#define _MULTI_FRAMED_RTP_SINK_H_

#include <xmedia.h>
#include <xqueue.h>

#include "rtsp_common.h"

namespace flvpusher {

class RtpInterface;
class OutPacketBuffer;

class MultiFramedRTPSink {
public:
  MultiFramedRTPSink(TaskScheduler *scheduler, RtpInterface *interface,
                     uint8_t rtp_payload_type, uint32_t rtp_timestamp_frequency,
                     const char *rtp_payload_format_name,
                     unsigned num_channels = 1);
  virtual ~MultiFramedRTPSink();

  typedef void (after_playing_func) (void *client_data);
  bool start_playing(xutil::Queue<xmedia::Frame *> &queue_src,
                     after_playing_func *after_func, void *after_client_data);
  virtual void stop_playing();

  uint8_t rtp_payload_type() const { return m_rtp_payload_type; }
  unsigned rtp_timestamp_frequency() const { return m_rtp_timestamp_frequency; }
  void set_rtp_timestamp_frequency(unsigned freq)
  { m_rtp_timestamp_frequency = freq; }
  const char *rtp_payload_format_name() const { return m_rtp_payload_format_name; }

  unsigned num_channels() const { return m_num_channels; }

  virtual char const *sdp_media_type() const = 0;
  virtual char *rtpmap_line() const;
  virtual char const *aux_sdp_line();

  uint16_t current_seq_num() const { return m_seq_num; }

  void set_packet_sizes(unsigned preferred_packet_size, unsigned max_packet_size);

  typedef void (on_send_error_func)(void* client_data);
  void set_on_send_error_func(on_send_error_func* on_send_error_func,
                              void* on_send_error_func_data) {
    m_on_send_error_func = on_send_error_func;
    m_on_send_error_data = on_send_error_func_data;
  }

  void set_stream_socket(int sockfd, unsigned char stream_channel_id);

  virtual RtpInterface *rtp_interface() const { return m_interface; }

protected:
  virtual bool continue_playing();

  static void on_source_closure(void *client_data);
  void on_source_closure();

  uint32_t ssrc() const { return m_ssrc; }
  uint32_t convert_to_rtp_timestamp(struct timeval tv);

  virtual void do_special_frame_handling(unsigned fragmentation_offset,
                                         unsigned char *frame_start,
                                         unsigned num_bytes_in_frame,
                                         struct timeval frame_presentation_time,
                                         unsigned num_remaining_bytes);
  virtual bool allow_fragmentation_after_start() const;
  virtual bool allow_other_frames_after_last_fragment() const;
  virtual bool frame_can_appear_after_packet_start(unsigned char const *frame_start,
                                                   unsigned num_bytes_in_frame) const;
  virtual unsigned special_header_size() const;
  virtual unsigned frame_special_header_size() const;
  virtual unsigned compute_overflow_for_new_frame(unsigned new_frame_size) const;

  bool is_first_packet() const { return m_is_first_packet; }
  bool is_first_frame_in_packet() const { return m_num_frames_used_so_far == 0; }
  unsigned cur_fragmentation_offset() const { return m_cur_fragmentation_offset; }
  void set_marker_bit();
  void set_timestamp(struct timeval frame_presentation_time);
  void set_special_header_word(unsigned word, unsigned word_position = 0);
  void set_special_header_bytes(unsigned char const *bytes, unsigned num_bytes,
                                unsigned byte_position = 0);
  void set_frame_specific_header_word(unsigned word, unsigned word_position = 0);
  void set_frame_specific_header_bytes(unsigned char const *bytes, unsigned num_bytes,
                                       unsigned byte_position = 0);
  void set_frame_padding(unsigned num_padding_bytes);
  unsigned num_frames_used_so_far() const { return m_num_frames_used_so_far; }
  unsigned our_max_packet_size() const { return m_our_max_packet_size; }

private:
  void build_and_send_packet(bool is_first_packet);
  void pack_frame();
  void send_packet_if_necessary();
  static void send_next(void *first_arg);

  static void after_getting_frame(void *client_data,
                                  unsigned num_bytes_read, unsigned num_truncated_bytes,
                                  struct timeval presentation_time, unsigned duration_in_microseconds);
  void after_getting_frame1(unsigned frame_size, unsigned num_truncated_bytes,
                            struct timeval presentation_time, unsigned duration_in_microseconds);
  bool is_too_big_for_a_packet(unsigned num_bytes) const;

protected:
  TaskScheduler *m_scheduler;
  xutil::Queue<xmedia::Frame *> *m_queue_src;
  RtpInterface *m_interface;
  uint8_t m_rtp_payload_type;
  uint64_t m_current_timestamp;
  uint16_t m_seq_num;

private:
  DISALLOW_COPY_AND_ASSIGN(MultiFramedRTPSink);

  after_playing_func *m_after_func;
  void *m_after_client_data;

  uint32_t m_ssrc, m_timestamp_base;
  uint32_t m_rtp_timestamp_frequency;
  const char *m_rtp_payload_format_name;
  unsigned m_num_channels;

  OutPacketBuffer *m_out_buf;

  unsigned m_num_frames_used_so_far;
  unsigned m_cur_fragmentation_offset;
  bool m_previous_frame_ended_fragmentation;

  bool m_is_first_packet;
  struct timeval m_next_send_time;
  unsigned m_timestamp_position;
  unsigned m_special_header_position;
  unsigned m_special_header_size;
  unsigned m_cur_frame_specific_header_position;
  unsigned m_cur_frame_specific_header_size;
  unsigned m_total_frame_specific_header_sizes;
  unsigned m_our_max_packet_size;

  on_send_error_func* m_on_send_error_func;
  void* m_on_send_error_data;

  TaskToken m_next_task;
  int32_t m_last_audio_timestamp;
};

}

#endif /* end of _MULTI_FRAMED_RTP_SINK_H_ */
