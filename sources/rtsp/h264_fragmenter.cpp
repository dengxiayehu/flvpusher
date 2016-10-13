#include "h264_fragmenter.h"

namespace flvpusher {

H264Fragmenter::H264Fragmenter(xutil::Queue<xmedia::Frame *> * queue_src,
                               unsigned input_buffer_max, unsigned max_output_packet_size) :
  m_queue_src(queue_src),
  m_input_buffer_size(input_buffer_max + 1), m_max_output_packet_size(max_output_packet_size),
  m_num_valid_data_bytes(1), m_cur_data_offset(1),
  m_last_fragment_completed_nal_unit(true),
  m_duration_in_microseconds(0),
  m_nalu_index_in_parser(0),
  m_frame(NULL),
  m_last_timestamp(0)
{
  m_presentation_time.tv_sec = m_presentation_time.tv_usec = 0;

  m_input_buffer = new unsigned char[m_input_buffer_size];
}

H264Fragmenter::~H264Fragmenter()
{
  SAFE_DELETE(m_frame);
  SAFE_DELETE_ARRAY(m_input_buffer);
}

void H264Fragmenter::get_next_frame(unsigned char *to, unsigned max_size,
                                    after_getting_func *func, void *data)
{
  m_to = to;
  m_max_size = max_size; // max buffer size to store the read data
  m_after_getting_func = func; // callback when frame read
  m_after_getting_client_data = data;

  if (m_num_valid_data_bytes == 1) {
    // We have no NAL unit data currently in the buffer. Read a new one
    if (m_nalu_index_in_parser == 0) {
      SAFE_DELETE(m_frame);

      if (m_queue_src->pop(m_frame) < 0) {
        // Pop a frame from input queue
        return;
      }

      // Split the frame into nalus
      m_vparser.process(m_frame->get_data(), m_frame->get_data_length());
    }

    unsigned frame_size = m_vparser.get_nalu_length(m_nalu_index_in_parser);
    unsigned num_truncated_bytes = 0;
    if (frame_size > m_input_buffer_size - 1) {
      LOGW("frame_size=%u, m_input_buffer_size-1=%u",
           frame_size, m_input_buffer_size - 1);
      num_truncated_bytes = frame_size - (m_input_buffer_size - 1);
      frame_size = m_input_buffer_size - 1;
    }
    memcpy(&m_input_buffer[1], m_vparser.get_nalu_data(m_nalu_index_in_parser), frame_size);

    struct timeval presentation_time;
    presentation_time.tv_sec = m_frame->get_dts()/1000;
    presentation_time.tv_usec = (m_frame->get_dts()%1000)*1000;

    if (++m_nalu_index_in_parser >= m_vparser.get_nalu_num()) {
      // this frame is done
      m_nalu_index_in_parser = 0;
      m_duration_in_microseconds = (m_frame->get_dts() - m_last_timestamp)*1000;
      m_last_timestamp = m_frame->get_dts();
    }

    after_getting_frame1(frame_size, num_truncated_bytes,
                         presentation_time, m_duration_in_microseconds);
  } else {
    // We have NAL unit data in the buffer. There are three cases to consider:
    // 1. There is a new NAL unit in the buffer, and it's small enough to deliver
    //    to the RTP sink.
    // 2. There is a new NAL unit in the buffer, but it's too large to deliver to
    //    the RTP sink in its entirety. Deliver the first fragment of this data,
    //    as a FU packet, with one extra preceding header byte (for the "FU header").
    // 3. There is a NAL unit in the buffer, and we've already deliverd some
    //    fragment(s) of this. Deliver the next fragment of this data,
    //    as a FU packet, with two (H.264) extra preceding header bytes
    //    (for the "NAL header" and the "FU header").
    if (m_max_size < m_max_output_packet_size) { // shouldn't happen
      LOGW("m_max_size(%u) is smaller than expected",
           m_max_size);
    } else {
      m_max_size = m_max_output_packet_size;
    }

    m_last_fragment_completed_nal_unit = true; // by default
    if (m_cur_data_offset == 1) { // case 1 or 2
      if (m_num_valid_data_bytes - 1 <= m_max_size) { // case 1
        memmove(m_to, &m_input_buffer[1], m_num_valid_data_bytes - 1);
        m_frame_size = m_num_valid_data_bytes - 1;
        m_cur_data_offset = m_num_valid_data_bytes;
      } else { // case 2
        // We need to send the NAL unit data as a FU packets. Deliver the first
        // packet now. Note that we add "NAL header" and "FU header" bytes to the front
        // of the packet (overwriting the existing "NAL header")
        m_input_buffer[0] = (m_input_buffer[1] & 0xE0) | 28; // FU indicator
        m_input_buffer[1] = 0x80 | (m_input_buffer[1] & 0x1F); //  FU header (with S bit)
        memmove(m_to, m_input_buffer, m_max_size);
        m_frame_size = m_max_size;
        m_cur_data_offset += m_max_size - 1;
        m_last_fragment_completed_nal_unit = false;
      }
    } else { // case 3
      // We are sending this NAL unit data as FU packets. We've already sent the
      // first packet (fragment). Now, send the next fragment. Note that we add 
      // "NAL header" and "FU header" bytes to the front. (We reuse these bytes that
      // we already sent for the first fragment, but clear the S bit, and add the E
      // bit if this is the last fragment.)
      unsigned num_extra_header_bytes = 2;
      m_input_buffer[m_cur_data_offset - 2] = m_input_buffer[0]; // FU indicator
      m_input_buffer[m_cur_data_offset - 1] = m_input_buffer[1]&~0x80; // FU header (no S bit)
      unsigned num_bytes_to_send = num_extra_header_bytes + (m_num_valid_data_bytes - m_cur_data_offset);
      if (num_bytes_to_send > m_max_size) {
        // We can't send all of the remaining data this time:
        num_bytes_to_send = m_max_size;
        m_last_fragment_completed_nal_unit = false;
      } else {
        // This is the last fragment:
        m_input_buffer[m_cur_data_offset - 1] |= 0x40; // set the E bit in the FU header
      }
      memmove(m_to, &m_input_buffer[m_cur_data_offset - num_extra_header_bytes], num_bytes_to_send);
      m_frame_size = num_bytes_to_send;
      m_cur_data_offset += num_bytes_to_send - num_extra_header_bytes;
    }

    if (m_cur_data_offset >= m_num_valid_data_bytes) {
      m_num_valid_data_bytes = m_cur_data_offset = 1;
    }

    m_after_getting_func(m_after_getting_client_data,
                         m_frame_size, 0,
                         m_presentation_time, m_duration_in_microseconds);
    m_duration_in_microseconds = 0;
  }
}

bool H264Fragmenter::picture_end_marker() const
{
  return m_nalu_index_in_parser == 0;
}

void H264Fragmenter::after_getting_frame1(unsigned frame_size, unsigned num_truncated_bytes,
                                          struct timeval presentation_time, unsigned duration_in_microseconds)
{
  m_num_valid_data_bytes += frame_size;
  UNUSED(num_truncated_bytes);
  m_presentation_time = presentation_time;
  m_duration_in_microseconds = duration_in_microseconds;

  get_next_frame(m_to, m_max_size,
                 m_after_getting_func, m_after_getting_client_data);
}

}
