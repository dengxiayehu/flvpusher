#include "h264_video_rtp_source.h"
#include "common/media_pusher.h"

namespace flvpusher {

SPropRecord *parse_s_prop_parm_str(const char *parm_str, unsigned &num_s_prop_records)
{
  // Make a copy of the input string, so we can replace the commas with '\0's:
  char *in_str = strdup(parm_str);
  if (!in_str) {
    num_s_prop_records = 0;
    return NULL;
  }

  // Count the number of commas (and thus the number of parameter sets):
  num_s_prop_records = 1;
  char *s;
  for (s = in_str; *s != '\0'; ++s) {
    if (*s == ',') {
      ++num_s_prop_records;
      *s = '\0';
    }
  }

  // Allocate and fill in the result array:
  SPropRecord *result_array = new SPropRecord[num_s_prop_records];
  s = in_str;
  for (unsigned i = 0; i < num_s_prop_records; ++i) {
    result_array[i].s_prop_bytes() =
      base64_decode(s, strlen(s), result_array[i].s_prop_length());
    s += strlen(s) + 1;
  }

  SAFE_FREE(in_str);
  return result_array;
}

H264VideoRTPSource::H264VideoRTPSource(
    TaskScheduler *scheduler,
    RtpInterface *interface,
    unsigned char rtp_payload_format,
    unsigned rtp_timestamp_frequency,
    const char *s_prop_parm_str,
    void *opaque) :
  MultiFramedRTPSource(scheduler, interface, rtp_payload_format, rtp_timestamp_frequency, opaque),
  m_sps(NULL), m_sps_size(0), m_pps(NULL), m_pps_size(0)
{
  unsigned num_s_prop_records;
  SPropRecord *s_prop_records =
    parse_s_prop_parm_str(s_prop_parm_str, num_s_prop_records);
  for (unsigned i = 0; i < num_s_prop_records; ++i) {
    if (s_prop_records[i].s_prop_length() == 0) continue;
    uint8_t nalu_type = (s_prop_records[i].s_prop_bytes()[0])&0x1F;
    if (nalu_type == 7) {
      m_sps_size = s_prop_records[i].s_prop_length();
      m_sps = (unsigned char *) malloc(m_sps_size);
      memcpy(m_sps, s_prop_records[i].s_prop_bytes(), m_sps_size);
    } else if (nalu_type == 8) {
      m_pps_size = s_prop_records[i].s_prop_length();
      m_pps = (unsigned char *) malloc(m_pps_size);
      memcpy(m_pps, s_prop_records[i].s_prop_bytes(), m_pps_size);
    }
  }
  SAFE_DELETE_ARRAY(s_prop_records);
}

H264VideoRTPSource::~H264VideoRTPSource()
{
  SAFE_FREE(m_sps);
  SAFE_FREE(m_pps);
}

bool H264VideoRTPSource::process_special_header(uint8_t *payload, unsigned payload_len,
                                                bool marker_bit, unsigned &result_special_header_size)
{
  unsigned num_bytes_to_skip = 0;

  if (payload_len < 4) return false;

  if (STARTCODE4(payload)) {
    payload += 4;
    num_bytes_to_skip += 4;
  } else if (STARTCODE3(payload)) {
    payload += 3;
    num_bytes_to_skip += 3;
  }
  payload_len -= num_bytes_to_skip;

  if (payload_len < 1) return false;
  m_cur_pkt_NALU_type = payload[0]&0x1F;
  switch (m_cur_pkt_NALU_type) {
    case 24:// STAP-A
      num_bytes_to_skip += 1;
      break;
    case 25: case 26: case 27: // STAP-B, MTAP16 or MTAP24
      num_bytes_to_skip += 3;
      break;
    case 28: case 29: { // FU-A or FU-B
                        // For these NALUs, the first two bytes are the FU indicator and the FU header.
                        // If the start bit is set, we reconstruct the original NAL header into byte 1:
      if (payload_len < 2) return false;
      unsigned char start_bit = payload[1]&0x80;
      unsigned char end_bit = payload[1]&0x40;
      if (start_bit) {
        m_current_packet_begins_frame = true;
        payload[1] = (payload[0]&0xE0)|(payload[1]&0x1F);
        num_bytes_to_skip += 1;
      } else {
        // The start bit is not set, so we skip both the FU indicator and header:
        m_current_packet_begins_frame = false;
        num_bytes_to_skip += 2;
      }
      m_current_packet_completes_frame = (end_bit != 0);
    } break;
    default:
      m_current_packet_begins_frame = m_current_packet_completes_frame = true;
      num_bytes_to_skip += 0;
      break;
  }
  result_special_header_size = num_bytes_to_skip;
  return true;
}

int H264VideoRTPSource::on_complete_frame1(FrameBuffer *frame)
{
  int nwritten = 0;
  size_t bytes_max = frame->size_bytes() + frame->size() * 4;
  uint8_t *buf = (uint8_t *) m_mem_holder.alloc(bytes_max);
  if (frame->frame_type() == kFrameKey && m_sps_size && m_pps_size) {
    bytes_max += (m_sps_size + m_pps_size + 2 * 4);
    buf = (uint8_t *) m_mem_holder.alloc(bytes_max);
    memcpy(buf+nwritten, nalu_startcode, 4); nwritten += 4;
    memcpy(buf+nwritten, m_sps, m_sps_size); nwritten += m_sps_size;
    memcpy(buf+nwritten, nalu_startcode, 4); nwritten += 4;
    memcpy(buf+nwritten, m_pps, m_pps_size); nwritten += m_pps_size;
  }
  for (FrameBuffer::Iterator it = frame->begin();
       it != frame->end();
       ++it) {
    Packet *pkt = frame->packet_at(it);
    if (pkt->current_packet_begins_frame()) {
      memcpy(buf+nwritten, nalu_startcode, 4);
      nwritten += 4;
    }
    memcpy(buf+nwritten, pkt->data_ptr(), pkt->size_bytes());
    nwritten += pkt->size_bytes();
  }

#ifdef XDEBUG
  LOGD("VIDEO frame: %05u~%05u, timestamp=%u, bytes_max=%u, nwritten=%d",
       frame->get_low_seq_num(), frame->get_high_seq_num(),
       frame->timestamp(), bytes_max, nwritten);
#endif

  if (m_opaque) {
    ((MediaPusher *) m_opaque)->on_frame(((frame->timestamp()-m_start_complete_timestamp)/(double)m_rtp_timestamp_frequency)*1000,
                                         buf, nwritten, 1);
  }

  if (m_file.is_opened())
    m_file.write_buffer(buf, nwritten);
  return 0;
}

}
