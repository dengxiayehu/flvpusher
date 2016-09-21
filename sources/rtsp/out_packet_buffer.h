#ifndef _OUT_PACKET_BUFFER_H_
#define _OUT_PACKET_BUFFER_H_

#include <xutil.h>

namespace flvpusher {

class OutPacketBuffer {
public:
  OutPacketBuffer(unsigned preferred_packet_size, unsigned max_packet_size,
                  unsigned max_buffer_size = 0);
  ~OutPacketBuffer();

  static unsigned max_size;
  static void increase_max_size_to(unsigned new_max_size)
  { if (new_max_size > OutPacketBuffer::max_size) OutPacketBuffer::max_size = new_max_size; }

  unsigned char *cur_ptr() const { return &m_buf[m_packet_start + m_cur_offset]; }
  unsigned total_bytes_available() const { return m_limit - (m_packet_start + m_cur_offset); }
  unsigned total_buffer_size() const { return m_limit; }
  unsigned char *packet() const { return &m_buf[m_packet_start]; }
  unsigned cur_packet_size() const { return m_cur_offset; }

  void increment(unsigned num_bytes) { m_cur_offset += num_bytes; }

  void enqueue(unsigned char const *from, unsigned num_bytes);
  void enqueue_word(uint32_t word);
  void insert(unsigned char const *from, unsigned num_bytes, unsigned to_position);
  void insert_word(uint32_t word, unsigned to_position);
  void extract(unsigned char *to, unsigned num_bytes, unsigned from_position);
  uint32_t extract_word(unsigned from_position);

  void skip_bytes(unsigned num_bytes);

  bool is_preferred_size() const { return m_cur_offset >= m_preferred; }
  bool would_overflow(unsigned num_bytes) const {  return m_cur_offset + num_bytes > m_max; }
  unsigned num_overflow_bytes(unsigned num_bytes) const { return m_cur_offset + num_bytes - m_max; }
  bool is_too_big_for_a_packet(unsigned num_bytes) const { return num_bytes > m_max; }

  void set_overflow_data(unsigned overflow_data_offset, unsigned overflow_data_size,
                         struct timeval const &presentation_time,
                         unsigned duration_in_microseconds);
  unsigned overflow_data_size() const { return m_overflow_data_size; }
  struct timeval overflow_presentation_time() const { return m_overflow_presentation_time; }
  unsigned overflow_duration_in_microseconds() const { return m_overflow_duration_in_microseconds; }
  bool have_overflow_data() const { return m_overflow_data_size > 0; }
  void use_overflow_data();

  void adjust_packet_start(unsigned num_bytes);
  void reset_packet_start();
  void reset_offset() { m_cur_offset = 0; }
  void reset_overflow_data() { m_overflow_data_offset = m_overflow_data_size = 0; }

private:
  unsigned m_packet_start, m_cur_offset, m_preferred, m_max, m_limit;
  unsigned char *m_buf;

  unsigned m_overflow_data_offset, m_overflow_data_size;
  struct timeval m_overflow_presentation_time;
  unsigned m_overflow_duration_in_microseconds;
};

}

#endif /* end of _OUT_PACKET_BUFFER_H_ */
