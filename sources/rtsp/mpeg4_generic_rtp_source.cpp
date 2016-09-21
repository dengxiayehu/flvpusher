#include "mpeg4_generic_rtp_source.h"
#include "common/media_pusher.h"

namespace flvpusher {

MPEG4GenericRTPSource::MPEG4GenericRTPSource(
    TaskScheduler *scheduler,
    RtpInterface *interface,
    unsigned char rtp_payload_format,
    unsigned rtp_timestamp_frequency,
    const char *medium_name,
    const char *mode,
    unsigned size_length,
    unsigned index_length,
    unsigned index_delta_length,
    const char *fmtp_config,
    void *opaque) :
  MultiFramedRTPSource(scheduler, interface, rtp_payload_format, rtp_timestamp_frequency, opaque),
  m_size_length(size_length), m_index_length(index_length),
  m_index_delta_length(index_delta_length),
  m_num_au_headers(0), m_next_au_header(0), m_au_headers(NULL)
{
  unsigned mime_type_length =
    strlen(medium_name) + strlen("/MPEG4-GENERIC") + 1;
  m_MIME_type = (char *) malloc(mime_type_length);
  if (m_MIME_type)
    sprintf(m_MIME_type, "%s/MPEG4-GENERIC", medium_name);

  m_fmtp_config = strdup(fmtp_config);
}

MPEG4GenericRTPSource::~MPEG4GenericRTPSource()
{
  SAFE_FREE(m_MIME_type);
  SAFE_DELETE_ARRAY(m_au_headers);
  SAFE_FREE(m_fmtp_config);
}

bool MPEG4GenericRTPSource::process_special_header(uint8_t *payload, unsigned payload_len,
                                                   bool marker_bit, unsigned &result_special_header_size)
{
  m_current_packet_begins_frame = m_current_packet_completes_frame;
  m_current_packet_completes_frame = marker_bit;

  result_special_header_size = 0;
  m_num_au_headers = 0;
  m_next_au_header = 0;
  SAFE_DELETE_ARRAY(m_au_headers);

  if (m_size_length > 0) {
    // The packet begins with a "AU Header Section".  Parse it, to
    // determine the "AU-header"s for each frame present in this packet:
    result_special_header_size += 2;
    if (payload_len < result_special_header_size)
      return false;

    unsigned au_headers_length = (payload[0]<<8)|payload[1];
    unsigned au_headers_length_bytes = (au_headers_length+7)/8;
    if (payload_len < result_special_header_size + au_headers_length_bytes)
      return false;
    result_special_header_size += au_headers_length_bytes;

    // Figure out how many AU-headers are present in the packet:
    int bits_avail = au_headers_length - (m_size_length + m_index_length);
    if (bits_avail >= 0 &&
        (m_size_length + m_index_delta_length) > 0)
      m_num_au_headers = 1 + bits_avail/(m_size_length + m_index_delta_length);
    if (m_num_au_headers > 0) {
      m_au_headers = new AUHeader[m_num_au_headers];
      // Fill in each header:
      GetBitContext gb;
      init_get_bits(&gb, &payload[2], au_headers_length);
      m_au_headers[0].size = get_bits(&gb, m_size_length);
      m_au_headers[0].index = get_bits(&gb, m_index_length);
      for (unsigned i = 1; i < m_num_au_headers; ++i) {
        m_au_headers[i].size = get_bits(&gb, m_size_length);
        m_au_headers[i].index = get_bits(&gb, m_index_delta_length);
      }
    }
  }
  return true;
}

const unsigned MPEG4GenericRTPSource::next_enclosed_frame_size(unsigned data_size)
{
  AUHeader *au_header = m_au_headers;
  if (!au_header) return data_size;
  unsigned num_au_headers = m_num_au_headers;

  if (m_next_au_header >= num_au_headers) {
    LOGE("next_enclosed_frame_size(%u): data error(%p,%u,%u)!",
         data_size, au_header, m_next_au_header, num_au_headers);
    return data_size;
  }

  au_header = &au_header[m_next_au_header++];
  return au_header->size <= data_size ? au_header->size : data_size;
}

static bool get_nibble(const char *&config_str,
                       uint8_t &result_nibble)
{
  char c = config_str[0];
  if (c == '\0') return false;

  if (c >= '0' && c <= '9')
    result_nibble = c - '0';
  else if (c >= 'A' && c <= 'F')
    result_nibble = 10 + c - 'A';
  else if (c >= 'a' && c <= 'f')
    result_nibble = 10 + c - 'a';
  else
    return false;

  ++config_str;
  return true;
}

static bool get_byte(const char *&config_str, uint8_t &result_byte)
{
  result_byte = 0;

  uint8_t first_nibble;
  if (!get_nibble(config_str, first_nibble)) return false;
  result_byte = first_nibble<<4;

  uint8_t second_nibble = 0;
  if (!get_nibble(config_str, second_nibble) && config_str[0] != '\0')
    return false;
  result_byte |= second_nibble;

  return true;
}

static uint8_t *parse_general_config_str(const char *config_str,
                                         unsigned &config_size)
{
  uint8_t *config = NULL;

  do {
    if (!config_str) break;
    config_size = (strlen(config_str)+1)/2;

    config = (uint8_t *) calloc(1, config_size);
    if (!config) break;

    unsigned i;
    for (i = 0; i < config_size; ++i)
      if (!get_byte(config_str, config[i])) break;
    if (i != config_size) break;

    return config;
  } while (0);

  config_size = 0;
  SAFE_FREE(config);
  return NULL;
}

unsigned sampling_freq_from_asc(const char *config_str)
{
  uint8_t *config = NULL;
  unsigned result = 0;

  do {
    unsigned config_size;
    config = parse_general_config_str(config_str, config_size);
    if (!config) break;

    LOGW("config[0]=%x, config[1]=%x", config[0], config[1]);

    if (config_size < 2) break;
    unsigned char sampling_freq_index = ((config[0]&0x07)<<1) | (config[1]>>7);
    if (sampling_freq_index < 15) {
      result = atoi(samplerate_idx_to_str(sampling_freq_index));
      break;
    }

    if (config_size < 5) break;
    result = ((config[1]&0x7F)<<17) | (config[2]<<9) | (config[3]<<1) | (config[4]>>7);
  } while (0);

  SAFE_FREE(config);
  return result;
}

int MPEG4GenericRTPSource::on_complete_frame1(FrameBuffer *frame)
{
  uint8_t *buf = (uint8_t *) m_mem_holder.alloc(
      AAC_ADTS_HEADER_SIZE + frame->size_bytes());
  unsigned config_size;
  uint8_t *asc_buf = parse_general_config_str(m_fmtp_config, config_size);
  if (generate_adts_header(asc_buf, frame->size_bytes(), buf) < 0) {
    LOGE("generate_adts_header failed (0x%02x 0x%02x)",
         asc_buf[0], asc_buf[1]);
    SAFE_FREE(asc_buf);
    return -1;
  }
  unsigned nwritten = AAC_ADTS_HEADER_SIZE;
  for (FrameBuffer::Iterator it = frame->begin();
       it != frame->end();
       ++it) {
    Packet *pkt = frame->packet_at(it);
    memcpy(buf+nwritten, pkt->data_ptr(), pkt->size_bytes());
    nwritten += pkt->size_bytes();
  }

#ifdef XDEBUG
  LOGD("AUDIO frame: %05u~%05u, timestamp=%u, nwritten=%d",
       frame->get_low_seq_num(), frame->get_high_seq_num(),
       frame->timestamp(), nwritten);
#endif

  if (m_opaque) {
    ((MediaPusher *) m_opaque)->on_frame(((frame->timestamp()-m_start_complete_timestamp)/(double)m_rtp_timestamp_frequency)*1000,
                                         buf, nwritten, 0);
  }

  if (m_file.is_opened())
    m_file.write_buffer(buf, nwritten);
  SAFE_FREE(asc_buf);
  return 0;
}

}
