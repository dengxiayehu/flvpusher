#include "out_packet_buffer.h"

namespace flvpusher {

unsigned OutPacketBuffer::max_size = 150000;

OutPacketBuffer::OutPacketBuffer(unsigned preferred_packet_size, unsigned max_packet_size, unsigned max_buffer_size) :
  m_preferred(preferred_packet_size), m_max(max_packet_size),
  m_overflow_data_size(0) {
  if (max_buffer_size == 0) max_buffer_size = max_size;
  unsigned max_num_packets = (max_buffer_size + (max_packet_size - 1))/max_packet_size;
  m_limit = max_num_packets*max_packet_size;
  m_buf = new unsigned char[m_limit];
  reset_packet_start();
  reset_offset();
  reset_overflow_data();
}

OutPacketBuffer::~OutPacketBuffer()
{
  SAFE_DELETE_ARRAY(m_buf);
}

void OutPacketBuffer::enqueue(unsigned char const *from, unsigned num_bytes)
{
  if (num_bytes > total_bytes_available()) {
#ifdef XDEBUG
    LOGW("OutPacketBuffer::enqueue() warning: %d > %d",
         num_bytes, total_bytes_available());
#endif
    num_bytes = total_bytes_available();
  }

  if (cur_ptr() != from) memmove(cur_ptr(), from, num_bytes);
  increment(num_bytes);
}

void OutPacketBuffer::enqueue_word(uint32_t word)
{
  uint32_t n_word = EHTONL(word);
  enqueue((unsigned char *) &n_word, 4);
}

void OutPacketBuffer::insert(unsigned char const *from, unsigned num_bytes, unsigned to_position)
{
  unsigned real_to_position = m_packet_start + to_position;
  if (real_to_position + num_bytes > m_limit) {
    if (real_to_position > m_limit) {
      return;
    }
    num_bytes = m_limit - real_to_position;
  }

  memmove(&m_buf[real_to_position], from, num_bytes);
  if (to_position + num_bytes > m_cur_offset) {
    m_cur_offset = to_position + num_bytes;
  }
}

void OutPacketBuffer::insert_word(uint32_t word, unsigned to_position)
{
  uint32_t n_word = EHTONL(word);
  insert((unsigned char *) &n_word, 4, to_position);
}

void OutPacketBuffer::extract(unsigned char *to, unsigned num_bytes, unsigned from_position)
{
  unsigned real_from_position = m_packet_start + from_position;
  if (real_from_position + num_bytes > m_limit) {
    if (real_from_position > m_limit) {
      return;
    }
    num_bytes = m_limit - real_from_position;
  }

  memmove(to, &m_buf[real_from_position], num_bytes);
}

uint32_t OutPacketBuffer::extract_word(unsigned from_position)
{
  uint32_t n_word;
  extract((unsigned char*)&n_word, 4, from_position);
  return ENTOHL(n_word);
}

void OutPacketBuffer::skip_bytes(unsigned num_bytes)
{
  if (num_bytes > total_bytes_available()) {
    num_bytes = total_bytes_available();
  }

  increment(num_bytes);
}

void OutPacketBuffer::set_overflow_data(unsigned overflow_data_offset, unsigned overflow_data_size,
                                        struct timeval const &presentation_time,
                                        unsigned duration_in_microseconds)
{
  m_overflow_data_offset = overflow_data_offset;
  m_overflow_data_size = overflow_data_size;
  m_overflow_presentation_time = presentation_time;
  m_overflow_duration_in_microseconds = duration_in_microseconds;
}

void OutPacketBuffer::use_overflow_data()
{
  enqueue(&m_buf[m_packet_start + m_overflow_data_offset], m_overflow_data_size);
  m_cur_offset -= m_overflow_data_size;
  reset_overflow_data();
}

void OutPacketBuffer::adjust_packet_start(unsigned num_bytes)
{
  m_packet_start += num_bytes;
  if (m_overflow_data_offset >= num_bytes) {
    m_overflow_data_offset -= num_bytes;
  } else {
    reset_overflow_data();
  }
}

void OutPacketBuffer::reset_packet_start()
{
  if (m_overflow_data_size > 0) {
    m_overflow_data_offset += m_packet_start;
  }
  m_packet_start = 0;
}

}
