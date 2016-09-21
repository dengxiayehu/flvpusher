#ifndef _H264_FRAGMENTER_H_
#define _H264_FRAGMENTER_H_

#include <xutil.h>
#include <xqueue.h>
#include <xmedia.h>

#include "common/raw_parser.h"

namespace flvpusher {

typedef void (after_getting_func) (void *client_data,
                                   unsigned frame_size, unsigned num_truncated_bytes,
                                   struct timeval presentation_time, unsigned duration_in_microseconds);

class H264Fragmenter {
public:
  H264Fragmenter(xutil::Queue<xmedia::Frame *> *queue_src,
                 unsigned input_buffer_max, unsigned max_output_packet_size);
  ~H264Fragmenter();

  bool last_fragment_completed_nal_unit() const { return m_last_fragment_completed_nal_unit; }
  void get_next_frame(unsigned char *to, unsigned max_size, after_getting_func *func, void *data);
  bool picture_end_marker() const;

private:
  void after_getting_frame1(unsigned frame_size, unsigned num_truncated_bytes,
                            struct timeval presentation_time, unsigned duration_in_microseconds);

private:
  DISALLOW_COPY_AND_ASSIGN(H264Fragmenter);
  xutil::Queue<xmedia::Frame *> *m_queue_src;
  unsigned m_input_buffer_size;
  unsigned m_max_output_packet_size;
  unsigned char *m_input_buffer;
  unsigned m_num_valid_data_bytes;
  unsigned m_cur_data_offset;
  bool m_last_fragment_completed_nal_unit;
  unsigned char *m_to;
  unsigned m_max_size;
  unsigned m_frame_size;
  struct timeval m_presentation_time;
  unsigned m_duration_in_microseconds;
  VideoRawParser m_vparser;
  unsigned m_nalu_index_in_parser;
  xmedia::Frame *m_frame;
  after_getting_func *m_after_getting_func;
  void *m_after_getting_client_data;
  int32_t m_last_timestamp;
};

}

#endif /* end of _H264_FRAGMENTER_H_ */
