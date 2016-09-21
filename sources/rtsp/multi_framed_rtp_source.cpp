#include "multi_framed_rtp_source.h"
#include "rtsp_common.h"
#include "rtp_interface.h"

using namespace ffmpeg;

namespace flvpusher {

MultiFramedRTPSource::MultiFramedRTPSource(
    TaskScheduler *scheduler,
    RtpInterface *interface,
    unsigned char rtp_payload_format,
    unsigned rtp_timestamp_frequency,
    void *opaque) :
  m_scheduler(scheduler),
  m_interface(interface),
  m_rtp_payload_format(rtp_payload_format),
  m_rtp_timestamp_frequency(rtp_timestamp_frequency),
  m_are_doing_network_reads(false),
  m_ssrc(0),
  m_current_packet_begins_frame(true),
  m_current_packet_completes_frame(true),
  m_received_pkt(false),
  m_last_received_seq_num(0),
  m_last_received_timestamp(0),
  m_start_complete_timestamp(0),
  m_opaque(opaque)
{
}

MultiFramedRTPSource::~MultiFramedRTPSource()
{
}

int MultiFramedRTPSource::start_receiving()
{
  if (m_are_doing_network_reads) {
    LOGE("This RTP source is already receiving data now");
    return -1;
  }

  m_are_doing_network_reads = true;
  m_scheduler->turn_on_background_read_handling(m_interface->get_sockfd(),
                                                (TaskScheduler::BackgroundHandlerProc *) &MultiFramedRTPSource::network_read_handler, this);
  return 0;
}

void MultiFramedRTPSource::network_read_handler(MultiFramedRTPSource *source, int mask)
{
  source->network_read_handler1(mask);
}

void MultiFramedRTPSource::network_read_handler1(int mask)
{
  uint8_t buf[MTU];
  int nread = m_interface->read(buf, sizeof(buf));
  if (nread < 0) {
    LOGE("Failed to receive RTP data");
    return;
  }

  if (nread < (int) sizeof(RTPHeaderRaw)) {
    // Ignore keep-alive packets
    return;
  }

  bool pkt_discarded = false;

  RTPHeaderRaw *hdr;
  RTPHeader header;
  const uint8_t *payload = NULL;
  unsigned payload_len = 0;
  unsigned payload_offset = 0;

  if (parse_rtp_header(buf, nread, &hdr, &payload, &payload_len, &header) < 0) {
    LOGE("Failed to decode RTP header");
    return;
  }

  header.timestamp += INITIAL_TIMESTAMP_OFFSET;

  unsigned special_header_size;
  FrameType ft = kFrameUnknown;
  bool is_first_pkt_in_frame = false;

  bool valid = false;
  if (!m_ssrc) {
    m_ssrc = header.ssrc;
    valid = true;
  } else if (header.ssrc == m_ssrc) {
    if (header.payload_type == m_rtp_payload_format)
      valid = true;
  }
  if (!valid) {
    pkt_discarded = true;
    goto on_return;
  }

  if (!payload_len) {
    pkt_discarded = true;
    goto on_return;
  }

  if (process_special_header((uint8_t *) payload, payload_len,
                             header.marker_bit, special_header_size)) {
    payload += special_header_size;
    payload_len -= special_header_size;
  }

  if (((uint16_t) (m_last_received_seq_num + 1) == header.sequence_number &&
       m_last_received_timestamp != header.timestamp) ||
      !m_received_pkt)
    is_first_pkt_in_frame = true;

  switch (codec_id()) {
    case CODEC_ID_H264:
      if (m_current_packet_begins_frame) {
        if (!is_first_pkt_in_frame && (payload[1]&0x80))
          is_first_pkt_in_frame = true;

        int nalu_type = payload[0]&0x1F;
        if (nalu_type == 0x07 || nalu_type == 0x08 ||
            nalu_type == 0x05 || nalu_type == 0x06 ) {
          ft = kFrameKey;
          if (header.marker_bit) {
            /* Combine the following frames into single one
             * SPS, timestamp:0, m:1
             * PPS, timestamp:0, m:1
             * SEI, timestamp:0, m:1
             * IDR, timestamp:0, m:0 ... */
            if (nalu_type == 0x07 ||
                (nalu_type != 0x07 &&
                 header.timestamp == m_last_received_timestamp))
              header.marker_bit = false;
          }
        } else
          ft = kFrameDelta;
      }
      break;
    case CODEC_ID_AAC:
      ft = kFrameKey;
      is_first_pkt_in_frame = true;
      break;
    default:
      LOGE("Unknown codec_id(%d)", codec_id());
      goto on_return;
  }

  do {
    unsigned cur_frame_size = next_enclosed_frame_size(payload_len);
    Packet *pkt = new Packet((uint8_t *) (payload + payload_offset), cur_frame_size,
                             header.sequence_number, header.timestamp, header.marker_bit,
                             ft, m_current_packet_begins_frame, is_first_pkt_in_frame);
    m_receiver.insert_packet(pkt,
                             (Receiver::CompleteFrameProc *) &MultiFramedRTPSource::on_complete_frame,
                             this);
    payload_offset += cur_frame_size;
    payload_len -= cur_frame_size;
    if (payload_len) {
      LOGE("Multi AU headers in one Audio rtp, not supported yet");
      goto on_return;
    }
  } while (payload_len);

on_return:
  m_received_pkt = true;
  m_last_received_seq_num = header.sequence_number;
  m_last_received_timestamp = header.timestamp;
}

int MultiFramedRTPSource::on_complete_frame(MultiFramedRTPSource *source,
                                            FrameBuffer *frame)
{
  if (!source->m_start_complete_timestamp)
    source->m_start_complete_timestamp = frame->timestamp();
  return source->on_complete_frame1(frame);
}

}
