#include <xutil.h>
#include <xmedia.h>

#include "multi_framed_rtp_sink.h"
#include "out_packet_buffer.h"
#include "rtp_interface.h"
#include "h264_fragmenter.h"
#include "mpeg4_generic_rtp_sink.h"

using namespace xutil;
using namespace xmedia;
using namespace std;

namespace flvpusher {

MultiFramedRTPSink::MultiFramedRTPSink(TaskScheduler *scheduler,
                                       RtpInterface *interface,
                                       uint8_t rtp_payload_type, uint32_t rtp_timestamp_frequency,
                                       const char *rtp_payload_format_name,
                                       unsigned num_channels) :
  m_scheduler(scheduler),
  m_queue_src(NULL),
  m_interface(interface),
  m_rtp_payload_type(rtp_payload_type),
  m_rtp_timestamp_frequency(rtp_timestamp_frequency),
  m_rtp_payload_format_name(strdup_(rtp_payload_format_name)),
  m_num_channels(num_channels),
  m_out_buf(NULL), m_cur_fragmentation_offset(0), m_previous_frame_ended_fragmentation(false),
  m_on_send_error_func(NULL), m_on_send_error_data(NULL),
  m_next_task(NULL),
  m_last_audio_timestamp(0)
{
  m_seq_num = 0;
  m_ssrc = random32();
  m_timestamp_base = 0;

  // Default max packet size (1500, minus allowance for IP, UDP, UMTP headers)
  // (Also, make it a multiple of 4 bytes, just in case that matters.)
  set_packet_sizes(1000, 1456);
}

MultiFramedRTPSink::~MultiFramedRTPSink()
{
  SAFE_DELETE(m_out_buf);
  free((char *) m_rtp_payload_format_name);
  if (m_next_task) {
    m_scheduler->unschedule_delayed_task(m_next_task);
  }
}

void MultiFramedRTPSink::set_packet_sizes(unsigned preferred_packet_size, unsigned max_packet_size)
{
  if (preferred_packet_size > max_packet_size ||
      preferred_packet_size == 0) {
    LOGW("preferred_packet_size=%u, max_packet_size=%u (ignored)",
       preferred_packet_size, max_packet_size);
    return;
  }

  SAFE_DELETE(m_out_buf);
  m_out_buf = new OutPacketBuffer(preferred_packet_size, max_packet_size);
  m_our_max_packet_size = max_packet_size;
}

void MultiFramedRTPSink::set_stream_socket(int sockfd, unsigned char stream_channel_id)
{
  m_interface->set_stream_socket(sockfd, stream_channel_id);
}

bool MultiFramedRTPSink::start_playing(Queue<Frame *> &queue_src,
                                       after_playing_func *after_func, void *after_client_data)
{
  if (m_queue_src) {
    LOGE("This sink is already beging played");
    return false;
  }

  m_queue_src = (Queue<Frame *> *) &queue_src;

  m_after_func = after_func;
  m_after_client_data = after_client_data;

  return continue_playing();
}

void MultiFramedRTPSink::stop_playing()
{
  m_queue_src = NULL;
  m_after_func = NULL;
}

void MultiFramedRTPSink::on_source_closure(void *client_data)
{
  MultiFramedRTPSink *sink = (MultiFramedRTPSink *) client_data;
  sink->on_source_closure();
}

void MultiFramedRTPSink::on_source_closure()
{
  m_queue_src = NULL;
  if (m_after_func) {
    (*m_after_func)(m_after_client_data);
  }
}

char const *MultiFramedRTPSink::sdp_media_type() const
{
  return "data";
}

char *MultiFramedRTPSink::rtpmap_line() const
{
  if (rtp_payload_type() >= 96) {
    string encoding_params_part;
    if (num_channels() != 1) {
      encoding_params_part = sprintf_("/%d", num_channels());
    } else {
      encoding_params_part = "";
    }
    char const * const rtpmap_fmt = "a=rtpmap:%d %s/%d%s"CRLF;
    unsigned rtpmap_fmt_size = strlen(rtpmap_fmt)
      + 3  + strlen(rtp_payload_format_name())
      + 20 + encoding_params_part.length();
    char *rtpmap_line = (char *) malloc(rtpmap_fmt_size);
    snprintf(rtpmap_line, rtpmap_fmt_size, rtpmap_fmt,
             rtp_payload_type(), rtp_payload_format_name(),
             rtp_timestamp_frequency(), STR(encoding_params_part));
    return rtpmap_line;
  } else {
    return strdup_("");
  }
}

char const *MultiFramedRTPSink::aux_sdp_line()
{
  return NULL;
}

bool MultiFramedRTPSink::continue_playing()
{
  build_and_send_packet(true);
  return true;
}

uint32_t MultiFramedRTPSink::convert_to_rtp_timestamp(struct timeval tv)
{
  uint32_t timestamp_increment = m_rtp_timestamp_frequency*tv.tv_sec;
  timestamp_increment += (uint32_t) (m_rtp_timestamp_frequency*(tv.tv_usec/1000000.0) + 0.5);

  uint32_t const rtp_timestamp = m_timestamp_base + timestamp_increment;

#ifdef XDEBUG
  LOGD("m_timestamp_base: 0x%08x, tv: %lu.%06ld\n\t=> RTP timestamp: 0x%08x",
       m_timestamp_base, tv.tv_sec, tv.tv_usec, rtp_timestamp);
#endif

  return rtp_timestamp;
}

void MultiFramedRTPSink::build_and_send_packet(bool is_first_packet)
{
  m_is_first_packet = is_first_packet;

  // Set up the RTP header:
  unsigned rtp_hdr = 0x80000000; // version 2
  rtp_hdr |= (m_rtp_payload_type << 16); // PT
  rtp_hdr |= m_seq_num; // sequence number
  m_out_buf->enqueue_word(rtp_hdr);

  m_timestamp_position = m_out_buf->cur_packet_size(); // timestamp
  m_out_buf->skip_bytes(4); // leave a hole for the timestamp

  m_out_buf->enqueue_word(ssrc()); // synchronization source (SSRC) identifier

  // Allow for a special, payload-format-specific header following the
  // RTP header:
  m_special_header_position = m_out_buf->cur_packet_size();
  m_special_header_size = special_header_size();
  m_out_buf->skip_bytes(m_special_header_size);

  m_total_frame_specific_header_sizes = 0;
  m_num_frames_used_so_far = 0;
  pack_frame();
}

void MultiFramedRTPSink::do_special_frame_handling(unsigned fragmentation_offset,
                                                   unsigned char *frame_start,
                                                   unsigned num_bytes_in_frame,
                                                   struct timeval frame_presentation_time,
                                                   unsigned num_remaining_bytes)
{
  if (is_first_frame_in_packet()) {
    set_timestamp(frame_presentation_time);
  }
}

bool MultiFramedRTPSink::allow_fragmentation_after_start() const
{
  return false;
}

bool MultiFramedRTPSink::allow_other_frames_after_last_fragment() const
{
  return false;
}

bool MultiFramedRTPSink::frame_can_appear_after_packet_start(unsigned char const *frame_start,
                                                             unsigned num_bytes_in_frame) const
{
  return true;
}

unsigned MultiFramedRTPSink::special_header_size() const
{
  return 0;
}

unsigned MultiFramedRTPSink::frame_special_header_size() const
{
  return 0;
}

unsigned MultiFramedRTPSink::compute_overflow_for_new_frame(unsigned new_frame_size) const
{
  return m_out_buf->num_overflow_bytes(new_frame_size);
}

void MultiFramedRTPSink::set_marker_bit()
{
  unsigned rtp_hdr = m_out_buf->extract_word(0);
  rtp_hdr |= 0x00800000;
  m_out_buf->insert_word(rtp_hdr, 0);
}

void MultiFramedRTPSink::set_timestamp(struct timeval frame_presentation_time)
{
  m_current_timestamp = convert_to_rtp_timestamp(frame_presentation_time);

  m_out_buf->insert_word(m_current_timestamp, m_timestamp_position);
}

void MultiFramedRTPSink::set_special_header_word(unsigned word, unsigned word_position)
{
  m_out_buf->insert_word(word, m_special_header_position + 4*word_position);
}

void MultiFramedRTPSink::set_special_header_bytes(unsigned char const *bytes, unsigned num_bytes,
    unsigned byte_position)
{
  m_out_buf->insert(bytes, num_bytes, m_special_header_position + byte_position);
}

void MultiFramedRTPSink::set_frame_specific_header_word(unsigned word, unsigned word_position)
{
  m_out_buf->insert_word(word, m_cur_frame_specific_header_position + 4*word_position);
}

void MultiFramedRTPSink::set_frame_specific_header_bytes(unsigned char const *bytes, unsigned num_bytes,
    unsigned byte_position)
{
  m_out_buf->insert(bytes, num_bytes, m_cur_frame_specific_header_position + byte_position);
}

void MultiFramedRTPSink::set_frame_padding(unsigned num_padding_bytes)
{
  if (num_padding_bytes > 0) {
    unsigned char padding_buffer[255];
    memset(padding_buffer, 0, num_padding_bytes);
    padding_buffer[num_padding_bytes-1] = num_padding_bytes;
    m_out_buf->enqueue(padding_buffer, num_padding_bytes);

    unsigned rtp_hdr = m_out_buf->extract_word(0);
    rtp_hdr |= 0x20000000;
    m_out_buf->insert_word(rtp_hdr, 0);
  }
}

void MultiFramedRTPSink::pack_frame()
{
  // First, see if we have an overflow frame that was too big for the last pkt
  if (m_out_buf->have_overflow_data()) {
    // Use this frame before reading a new one from the source
    unsigned frame_size = m_out_buf->overflow_data_size();
    struct timeval presentation_time = m_out_buf->overflow_presentation_time();
    unsigned duration_in_microseconds = m_out_buf->overflow_duration_in_microseconds();
    m_out_buf->use_overflow_data();

    after_getting_frame1(frame_size, 0, presentation_time, duration_in_microseconds);
  } else {
    // Normal case: we need to read a new frame from the source
    if (!m_queue_src) return;

    m_cur_frame_specific_header_position = m_out_buf->cur_packet_size();
    m_cur_frame_specific_header_size = frame_special_header_size();
    m_out_buf->skip_bytes(m_cur_frame_specific_header_size);
    m_total_frame_specific_header_sizes += m_cur_frame_specific_header_size;

    if (!strcmp(sdp_media_type(), "video")) {
      H264Fragmenter *h264_fragmenter = (H264Fragmenter *) m_queue_src;
      h264_fragmenter->get_next_frame(m_out_buf->cur_ptr(), m_out_buf->total_bytes_available(),
                                      after_getting_frame, this);
    } else {
      Frame *f = NULL;
      if (m_queue_src->pop(f) == 0) {
        struct timeval presentation_time = { f->get_dts()/1000, (f->get_dts()%1000)*1000 };
        memcpy(m_out_buf->cur_ptr(), f->get_data()+7, f->get_data_length()-7);

        after_getting_frame(this, f->get_data_length()-7, 0,
                            presentation_time, (f->get_dts() - m_last_audio_timestamp)*1000);
        m_last_audio_timestamp = f->get_dts();
      }
      SAFE_DELETE(f);
    }
  }
}

void MultiFramedRTPSink::send_packet_if_necessary()
{
  if (m_num_frames_used_so_far > 0) {
    // Send the packet:
    if (m_interface->write(m_out_buf->packet(), m_out_buf->cur_packet_size()) < 0) {
      if (m_on_send_error_func) {
        (*m_on_send_error_func)(m_on_send_error_data);
      }
    }
    ++m_seq_num; // for next time
  }

  if (m_out_buf->have_overflow_data() &&
      m_out_buf->total_bytes_available() > m_out_buf->total_buffer_size()/2) {
    // Efficiency hack: Reset the packet start pointer to just in front of
    // the overflow data (allowing for the RTP header and special headers),
    // so that we probably don't have to "memmove" the overflow data
    // into place when building the next packet:
    unsigned new_packet_start = m_out_buf->cur_packet_size() -
      (rtp_header_size + m_special_header_size + frame_special_header_size());
    m_out_buf->adjust_packet_start(new_packet_start);
  } else {
    // Normal case: Reset the packet start pointer back to the start:
    m_out_buf->reset_packet_start();
  }
  m_out_buf->reset_offset();
  m_num_frames_used_so_far = 0;

  struct timeval now;
  gettimeofday(&now, NULL);
  int secs_diff = m_next_send_time.tv_sec - now.tv_sec;
  int64_t usecs_to_go = secs_diff*1000000 + (m_next_send_time.tv_usec - now.tv_usec);
  if (usecs_to_go < 0 || secs_diff < 0) {
    usecs_to_go = 0;
  }
  m_next_task = m_scheduler->schedule_delayed_task(usecs_to_go, send_next, this);
}

void MultiFramedRTPSink::send_next(void *first_arg)
{
  MultiFramedRTPSink *sink = (MultiFramedRTPSink *) first_arg;
  sink->build_and_send_packet(false);
}

void MultiFramedRTPSink::after_getting_frame(void *client_data,
                                             unsigned num_bytes_read, unsigned num_truncated_bytes,
                                             struct timeval presentation_time, unsigned duration_in_microseconds)
{
  MultiFramedRTPSink *sink = (MultiFramedRTPSink *) client_data;
  sink->after_getting_frame1(num_bytes_read, num_truncated_bytes,
                             presentation_time, duration_in_microseconds);
}

void MultiFramedRTPSink::after_getting_frame1(unsigned frame_size, unsigned num_truncated_bytes,
                                              struct timeval presentation_time, unsigned duration_in_microseconds)
{
  if (m_is_first_packet) {
    // Record the fact that we're are starting to play now:
    gettimeofday(&m_next_send_time, NULL);
  }

  if (num_truncated_bytes > 0) {
    unsigned const buffer_size = m_out_buf->total_bytes_available();
    LOGW("The input frame data was too large for our buffer size (%u). %u bytes of trailing data was dropped!",
         buffer_size, num_truncated_bytes);
  }
  unsigned cur_fragmentation_offset = m_cur_fragmentation_offset;
  unsigned num_frame_bytes_to_use = frame_size;
  unsigned overflow_bytes = 0;

  // If we have already packed one or more frames into this packet,
  // check whether this new frame is eligible to be packed after them.
  // (This is indenpendent of whether the packet has enough room for this
  // new frame; that check comes later)
  if (m_num_frames_used_so_far > 0) {
    if ((m_previous_frame_ended_fragmentation && !allow_other_frames_after_last_fragment()) ||
        !frame_can_appear_after_packet_start(m_out_buf->cur_ptr(), frame_size)) {
      // Save away this frame for next time:
      num_frame_bytes_to_use = 0;
      m_out_buf->set_overflow_data(m_out_buf->cur_packet_size(), frame_size,
                                   presentation_time, duration_in_microseconds);
    }
  }
  m_previous_frame_ended_fragmentation = false;

  if (num_frame_bytes_to_use > 0) {
    // Check whether this frame overflows the packet
    if (m_out_buf->would_overflow(frame_size)) {
      // Don't use this frame now; instead, save it as overflow data, and
      // send it in the next packet instead. However, if the frame is too
      // big to fit in a packet by itself, then we need to fragment it (and
      // use some of it in this packet, if the payload format permits this.)
      if (is_too_big_for_a_packet(frame_size) &&
          (m_num_frames_used_so_far == 0 || allow_fragmentation_after_start())) {
        // We need to fragment this frame, and use some of it now:
        overflow_bytes = compute_overflow_for_new_frame(frame_size);
        num_frame_bytes_to_use -= overflow_bytes;
        m_cur_fragmentation_offset += num_frame_bytes_to_use;
      } else {
        // We don't use any of this frame:
        overflow_bytes = frame_size;
        num_frame_bytes_to_use = 0;
      }
      m_out_buf->set_overflow_data(m_out_buf->cur_packet_size() + num_frame_bytes_to_use,
                                   overflow_bytes, presentation_time, duration_in_microseconds);
    } else if (m_cur_fragmentation_offset > 0) {
      // This is the last fragment of a frame that was fragmented over
      // more than one packet. Do any special handing for this case:
      m_cur_fragmentation_offset = 0;
      m_previous_frame_ended_fragmentation = true;
    }
  }

  if (num_frame_bytes_to_use == 0 && frame_size > 0) {
    // Send our packet now, because we have filled it up:
    send_packet_if_necessary();
  } else {
    // Use this frame in our outgoing packet:
    unsigned char *frame_start = m_out_buf->cur_ptr();
    m_out_buf->increment(num_frame_bytes_to_use);

    // Here's where any payload format specific processing gets done:
    do_special_frame_handling(cur_fragmentation_offset, frame_start,
                              num_frame_bytes_to_use,
                              presentation_time,
                              overflow_bytes);

    ++m_num_frames_used_so_far;

    // Update the time at which the next packet should be sent, based
    // on the duration of the frame that we just packed into it.
    // However, if this frame has overflow data remaining, then don't
    // count its duratin yet.
    if (overflow_bytes == 0) {
      m_next_send_time.tv_usec += duration_in_microseconds;
      m_next_send_time.tv_sec += m_next_send_time.tv_usec/1000000;
      m_next_send_time.tv_usec %= 1000000;
    }

    // Send our packet now if
    // (i) it's already at our preferred size or
    // (ii) (heuristic) another frame of the same size as the one we just
    //      read would overflow the packet, or
    // (iii) it contains the last fragment of a fragmented frame, and we 
    //      don't allow anything else to follow this or
    // (iv) one frame per packet is allowed:
    if (m_out_buf->is_preferred_size() ||
        m_out_buf->would_overflow(num_frame_bytes_to_use) ||
        (m_previous_frame_ended_fragmentation && !allow_other_frames_after_last_fragment()) ||
        !frame_can_appear_after_packet_start(m_out_buf->cur_ptr() - frame_size, frame_size)) {
      send_packet_if_necessary();
    } else {
      pack_frame();
    }
  }
}

bool MultiFramedRTPSink::is_too_big_for_a_packet(unsigned num_bytes) const
{
  num_bytes += rtp_header_size + special_header_size() + frame_special_header_size();
  return m_out_buf->is_too_big_for_a_packet(num_bytes);
}

}
