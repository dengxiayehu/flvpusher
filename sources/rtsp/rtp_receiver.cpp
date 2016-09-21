#include <xlog.h>
#include <memory>

#include "rtp_receiver.h"

//#define XDEBUG

using namespace xutil;
using namespace std;

namespace flvpusher {

static void parse_one_byte_extension_header(struct RTPHeader *header,
                                            const uint8_t *ptr_rtp_data_extension_end,
                                            const uint8_t *ptr);
static uint8_t parse_padding_bytes(const uint8_t* ptr_rtp_data_extension_end,
                                   const uint8_t* ptr);

int parse_rtp_header(const uint8_t *pkt, int pkt_len,
                     RTPHeaderRaw **hdr,
                     const uint8_t **payload, unsigned *payload_len,
                     RTPHeader *rtp_header)
{
  const uint8_t *ptr_rtp_data_end = pkt + pkt_len;
  const uint8_t *ptr;
  uint8_t padding_length = 0;

  // Assume RTP header at the start of packet. We'll verify this later.
  *hdr = (RTPHeaderRaw *) pkt;

  // Check RTP header sanity.
  if ((*hdr)->v != 2 /*RTP_VERSION*/) {
    return -1;
  }

  rtp_header->marker_bit = (*hdr)->m;
  rtp_header->payload_type = (uint8_t) (*hdr)->pt;
  rtp_header->sequence_number = ENTOHS((*hdr)->seq);
  rtp_header->timestamp = ENTOHL((*hdr)->ts);
  rtp_header->ssrc = ENTOHL((*hdr)->ssrc);

  // Handle CSRC about
  rtp_header->num_CSRCs = (uint8_t) (*hdr)->cc;
  ptr = ((uint8_t *) (*hdr)) + 12 /* CSRC's offset, fixed is 12 */;
  for (unsigned i = 0; i < (*hdr)->cc; ++i, ptr += 4) {
    uint32_t CSRC = ENTOHL(* (uint32_t *) ptr);
    rtp_header->arr_of_CSRCs[i] = CSRC;
  }

  rtp_header->header_length = 12 + (*hdr)->cc * 4;

  rtp_header->extension.transmission_time_offset = 0;
  rtp_header->extension.absolute_send_time = 0;

  // Adjust offset if RTP extension is used. 
  if ((*hdr)->x) {
      /* RTP header extension, RFC 3550.
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |      defined by profile       |           length              |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                        header extension                       |
       |                             ....                              |
       */
    const ptrdiff_t remain = ptr_rtp_data_end - ptr;
    uint16_t defined_by_profile;
    uint16_t length;
    if (remain < 4) {
      LOGE("RTP extension format error");
      return -1;
    }

    rtp_header->header_length += 4;

    defined_by_profile = ENTOHS(*(uint16_t *) ptr);
    ptr += 2;
    length = ENTOHS(*(uint16_t *) ptr);
    ptr += 2;
    length *= 4; // In octs

    if (remain < 4 + length) {
      LOGE("RTP extension format error");
      return -1;
    }

    if (defined_by_profile == kRtpOneByteHeaderExtensionId) {
      const uint8_t* ptr_rtp_data_extension_end = ptr + length;
      parse_one_byte_extension_header(rtp_header, ptr_rtp_data_extension_end, ptr);
    }

    rtp_header->header_length += length;
    ptr = pkt + rtp_header->header_length;
  }

  // If red packet, get the real payload type
  if (rtp_header->payload_type == PAYLOAD_TYPE_RED) {
    rtp_header->payload_type = *ptr++;
    (*hdr)->pt = rtp_header->payload_type;
  }

  // Find and set payload.
  *payload = ptr;
  *payload_len = ptr_rtp_data_end - ptr;

  // Remove payload padding if any
  if ((*hdr)->p && *payload_len > 0) {
    padding_length = ((uint8_t*)(*payload))[*payload_len - 1];
    if (padding_length <= *payload_len)
      *payload_len -= padding_length;
  }

  rtp_header->padding_length = padding_length;

#ifdef XDEBUG
  LOGD("Payload:%p payload_len:%4u M:%d pt:%u seq:%u timestamp:%u ssrc:0x%x num_CSRCs:%u padding_length:%u header_length:%u",
       *payload, *payload_len, rtp_header->marker_bit, rtp_header->payload_type, rtp_header->sequence_number, rtp_header->timestamp, rtp_header->ssrc, rtp_header->num_CSRCs, rtp_header->padding_length, rtp_header->header_length);
#endif
  return 0;
}

static void parse_one_byte_extension_header(struct RTPHeader *header,
                                            const uint8_t *ptr_rtp_data_extension_end,
                                            const uint8_t *ptr)
{
  while (ptr_rtp_data_extension_end - ptr > 0) {
    //  0
    //  0 1 2 3 4 5 6 7
    // +-+-+-+-+-+-+-+-+
    // |  ID   |  len  |
    // +-+-+-+-+-+-+-+-+

    const uint8_t id = (*ptr & 0xf0) >> 4;
    const uint8_t len = (*ptr & 0x0f);

    RTPExtensionType type;
    uint8_t num_bytes;

    ptr++;

    if (id == 15) {
      LOGE("Ext id: 15 encountered, parsing terminated.");
      return;
    }

    // NOTE: We use fixed extension map:
    // id 1 for kRtpExtensionTransmissionTimeOffset;
    // id 3 for kRtpExtensionAbsoluteSendTime
    switch (id) {
      case 1:     type = kRtpExtensionTransmissionTimeOffset; break;
      case 3:     type = kRtpExtensionAbsoluteSendTime;       break;
      default:    type = kRtpExtensionNone;                   break; // walk through
    }

    switch (type) {
      case kRtpExtensionTransmissionTimeOffset: {
        int32_t transmission_time_offset;

        if (len != 2) {
          LOGE("Incorrect transmission time offset len: %d", len);
          return;
        }

        //  0                   1                   2                   3
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |  ID   | len=2 |              transmission offset              |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        transmission_time_offset = *ptr++ << 16;
        transmission_time_offset += *ptr++ << 8;
        transmission_time_offset += *ptr++;
        header->extension.transmission_time_offset = transmission_time_offset;
        if (transmission_time_offset & 0x800000) {
          // Negative offset, correct sign for Word24 to Word32.
          header->extension.transmission_time_offset |= 0xFF000000;
        }
        break;
      }
      case kRtpExtensionAudioLevel: {
        //   --- Only used for debugging ---
        //  0                   1                   2                   3
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |  ID   | len=0 |V|   level     |      0x00     |      0x00     |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //

        // Parse out the fields but only use it for debugging for now.
        // const uint8_t V = (*ptr & 0x80) >> 7;
        // const uint8_t level = (*ptr & 0x7f);
        // DEBUG_PRINT("RTP_AUDIO_LEVEL_UNIQUE_ID: ID=%u, len=%u, V=%u,
        // level=%u", ID, len, V, level);
        break;
      }
      case kRtpExtensionAbsoluteSendTime: {
        uint32_t absolute_send_time;

        if (len != 2) {
          LOGE("Incorrect absolute send time len: %d", len);
          return;
        }
        //  0                   1                   2                   3
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |  ID   | len=2 |              absolute send time               |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        absolute_send_time = *ptr++ << 16;
        absolute_send_time += *ptr++ << 8;
        absolute_send_time += *ptr++;
        header->extension.absolute_send_time = absolute_send_time;
        break;
      }
      default:
        LOGE("Extension type not implemented.");
        return;
    }
    num_bytes = parse_padding_bytes(ptr_rtp_data_extension_end, ptr);
    ptr += num_bytes;
  }
}

static uint8_t parse_padding_bytes(const uint8_t* ptr_rtp_data_extension_end,
                                   const uint8_t* ptr)
{
  uint8_t num_zero_bytes = 0;

  while (ptr_rtp_data_extension_end - ptr > 0) {
    if (*ptr != 0) {
      return num_zero_bytes;
    }
    ptr++;
    num_zero_bytes++;
  }
  return num_zero_bytes;
}


static const char *frame_type_str(const FrameType frame_type)
{
  return frame_type == kFrameKey ? "key" :
    frame_type == kFrameDelta ? "delta" : "unknown";
}


Packet::Packet(const uint8_t *ptr, const uint32_t size,
               uint16_t seq_num, uint32_t timestamp, bool marker_bit,
               FrameType ft, bool current_packet_begins_frame,
               bool first_packet) :
  m_size_bytes(size),
  m_seq_num(seq_num), m_timestamp(timestamp), m_marker_bit(marker_bit),
  m_frame_type(ft), m_current_packet_begins_frame(current_packet_begins_frame),
  m_first_packet(first_packet)
{
  m_data_ptr = (uint8_t *) malloc(m_size_bytes);
  memcpy(m_data_ptr, ptr, m_size_bytes);
}

Packet::~Packet()
{
  SAFE_FREE(m_data_ptr);
}

void Packet::reset()
{
  m_data_ptr = NULL;
  m_size_bytes = 0;
  m_seq_num = 0;
  m_timestamp = 0;
  m_marker_bit = false;
  m_frame_type = kFrameUnknown;
  m_first_packet = false;
}

const std::string Packet::to_string() const
{
  return sprintf_(
      "payload:%p payload_len:%4u M:%d seq:%u timestamp:%u frame_type:%s",
      m_data_ptr, m_size_bytes, m_marker_bit, m_seq_num, m_timestamp,
      frame_type_str(m_frame_type));
}


FrameBuffer::FrameBuffer() :
  m_frame_type(kFrameUnknown),
  m_empty_seq_num_high(-1), m_empty_seq_num_low(-1),
  m_timestamp(0),
  m_state(kStateEmpty),
  m_complete(false)
{
}

FrameBuffer::~FrameBuffer()
{
  reset();
}

int FrameBuffer::get_high_seq_num() const
{
  if (m_packets.empty())
    return m_empty_seq_num_high;

  int high_seq_num = MAP_VAL(--m_packets.end())->seq_num();
  if (m_empty_seq_num_high == -1)
    return high_seq_num;

  return latest_seq_num(high_seq_num, (uint16_t) m_empty_seq_num_high);
}

int FrameBuffer::get_low_seq_num() const
{
  if (m_packets.empty())
    return m_empty_seq_num_high;

  return MAP_VAL(m_packets.begin())->seq_num();
}

void FrameBuffer::reset()
{
  m_frame_type = kFrameUnknown;
  FOR_MAP(m_packets, uint16_t, Packet *, it)
    SAFE_DELETE(MAP_VAL(it));
  m_packets.clear();
  m_empty_seq_num_high = m_empty_seq_num_low = -1;
  m_timestamp = 0;
  m_state = kStateEmpty;
  m_complete = false;
}

FrameBufferStateEnum FrameBuffer::get_state(uint32_t *ptimestamp) const
{
  if (ptimestamp)
    *ptimestamp = timestamp();
  return m_state;
}

FrameBufferEnum FrameBuffer::insert_packet(const Packet *pkt, uint64_t now)
{
  // Is this packet part of this frame?
  if (timestamp() && timestamp() != pkt->timestamp())
    return kTimeStampError;

  // Sanity check
  if (!pkt->data_ptr() && pkt->size_bytes() > 0)
    return kSizeError;

  if (pkt->first_packet() ||
      (m_frame_type == kFrameUnknown && pkt->frame_type() != kFrameUnknown))
    m_frame_type = pkt->frame_type();

  if (get_state() == kStateEmpty) {
    // First packet (empty and/or media) inserted into this frame.
    // store some info and set some initial values.
    m_timestamp = pkt->timestamp();
    if (pkt->size_bytes() > 0) {
      // First media packet
      set_state(kStateIncomplete);
    }
  }

  if (m_packets.find(pkt->seq_num()) != m_packets.end())
    return kDuplicatePacket;
  if (m_packets.size() >= kMaxPacketsInFrame)
    return kSizeError;

  // Insert this packet into list
  m_packets.insert(pair<uint16_t, Packet *>(pkt->seq_num(), (Packet *) pkt));

  // Whether is a complete frame
  update_complete_session();

  if (complete()) {
    set_state(kStateComplete);
    return kCompleteSession;
  }
  return kIncomplete;
}

void FrameBuffer::set_state(FrameBufferStateEnum state)
{
  if (get_state() == state)
    return;

  switch (state) {
    case kStateIncomplete:
      // We can go to this state from state kStateEmpty
      assert(get_state() == kStateEmpty);
      // Do nothing, we received a packet
      break;

    case kStateComplete:
      assert(get_state() == kStateEmpty ||
          get_state() == kStateIncomplete);
      break;

    case kStateEmpty:
      break;
  }

  m_state = state;
}

void FrameBuffer::update_complete_session()
{
  if (MAP_VAL(m_packets.begin())->first_packet() &&
      MAP_VAL(--m_packets.end())->marker_bit()) {
    if (m_packets.size() == 1)
      m_complete = true;
    else {
      bool complete_session = true;
      for (PacketList::iterator it = m_packets.begin(), prev_it = it++;
          it != m_packets.end();
          prev_it = it++) {
        if (!in_sequence(MAP_VAL(it), MAP_VAL(prev_it))) {
          complete_session = false;
          break;
        }
      }
      m_complete = complete_session;
    }
  }
}

bool FrameBuffer::in_sequence(const Packet *pkt, const Packet *prev_pkt)
{
  return pkt == prev_pkt || (uint16_t) (prev_pkt->seq_num() + 1) == pkt->seq_num();
}

size_t FrameBuffer::size_bytes() const
{
  size_t bytes = 0;
  FOR_MAP_CONST(m_packets, uint16_t, Packet *, it)
    bytes += MAP_VAL(it)->size_bytes();
  return bytes;
}


FrameBuffer *FrameMap::find_frame(uint32_t timestamp)
{
  Iterator it = m_frames.find(timestamp);
  if (it == end())
    return NULL;
  return MAP_VAL(it);
}

void FrameMap::reset(FrameList &free_frames)
{
  FOR_MAP(m_frames, uint32_t, FrameBuffer *, it)
    free_frames.push(MAP_VAL(it));
  clear();
}

int FrameMap::recycle_frames_until_key_frame(bool &key_frame_found,
                                             FrameList &free_frames)
{
  int drop_count = 0;

  while (!empty()) {
    Iterator it = begin();
    // Throw at least one frame
    FrameBuffer *frame = MAP_VAL(it);
    LOGI("Recycling: type=%s, low_seq_num=%u, high_seq_num=%u",
         frame_type_str(frame->frame_type()), frame->get_low_seq_num(), frame->get_high_seq_num());
    frame->reset();
    free_frames.push(frame);
    ++drop_count;
    m_frames.erase(it++);
    if (it != end() && MAP_VAL(it)->frame_type() == kFrameKey) {
      key_frame_found = true;
      return drop_count;
    }
  }
  key_frame_found = false;
  return drop_count;
}

FrameBuffer *FrameMap::pop_frame(uint32_t timestamp)
{
  Iterator it = m_frames.find(timestamp);
  if (it == end())
    return NULL;
  FrameBuffer *frame = MAP_VAL(it);
  m_frames.erase(it);
  return frame;
}

void FrameMap::insert_frame(FrameBuffer *frame)
{
  m_frames.insert(pair<uint32_t, FrameBuffer *>(frame->timestamp(), frame));
}

int FrameMap::cleanup_old_or_empty_frames(DecodingState *ds, FrameList &free_frames)
{
  int drop_count = 0;
  while (!empty()) {
    Iterator it = begin();
    FrameBuffer *oldest_frame = MAP_VAL(it);

    bool remove_frame = false;
    if (oldest_frame->get_state() == kStateEmpty &&
        size() > 1) {
      // This frame is empty, try to update the last decoded state and
      // drop it if successfully
      remove_frame = ds->update_empty_frame(oldest_frame);
    } else
      remove_frame = ds->is_old_frame(oldest_frame);
    if (!remove_frame)
      break;

    free_frames.push(oldest_frame);
    ++drop_count;
    m_frames.erase(it);
  }
  return drop_count;
}


DecodingState::DecodingState() :
  m_seq_num(0), m_timestamp(0), m_in_initial_state(true)
{
}

bool DecodingState::is_old_packet(const Packet *pkt)
{
  if (m_in_initial_state)
    return false;

  return !is_newer_timestamp(pkt->timestamp(), m_timestamp);
}

void DecodingState::update_old_packet(const Packet *pkt)
{
  if (pkt->timestamp() == m_timestamp) {
    // Late packet belonging to the last decoded frame - make sure we update the
    // last decoded sequence number.
    m_seq_num = latest_seq_num(pkt->seq_num(), m_seq_num);
  }
}

void DecodingState::reset()
{
  m_seq_num = 0;
  m_timestamp = 0;
  m_in_initial_state = true;
}

bool DecodingState::update_empty_frame(const FrameBuffer *frame)
{
  bool empty_packet =
    frame->get_high_seq_num() == frame->get_low_seq_num();

  if (m_in_initial_state && empty_packet) {
    // Drop empty packets as long as we are in the initial state
    return true;
  }
  if ((empty_packet && continuous_seq_num((uint16_t) frame->get_high_seq_num())) ||
      continuous_frame(frame)) {
    // Continuous empty packets or continuous frames can be dropped if we
    // advance the sequence number.
    m_seq_num = (uint16_t) frame->get_high_seq_num();
    m_timestamp = frame->timestamp();
    return true;
  }
  return false;
}

bool DecodingState::continuous_seq_num(uint16_t seq_num) const
{
  return seq_num == (uint16_t) (m_seq_num + 1);
}

bool DecodingState::continuous_frame(const FrameBuffer *frame) const
{
  assert(frame);
  // A key frame is always considered continuous as it doesn't refer to any
  // frames and therefore won't introduce any errors even if prior frames are
  // missing.
  if (frame->frame_type() == kFrameKey)
    return true;
  // When in the initial state we always require a key frame to start decoding.
  if (m_in_initial_state)
    return false;
  return true;
}

void DecodingState::copy_from(const DecodingState &ds)
{
  m_seq_num = ds.m_seq_num;
  m_timestamp = ds.m_timestamp;
  m_in_initial_state = ds.m_in_initial_state;
}

void DecodingState::set_state(const FrameBuffer *frame)
{
  assert(frame && frame->get_high_seq_num() >= 0);
  m_seq_num = frame->get_high_seq_num();
  m_timestamp = frame->timestamp();
  m_in_initial_state = false;
}

bool DecodingState::is_old_frame(const FrameBuffer *frame) const
{
  assert(frame);
  if (m_in_initial_state)
    return false;
  return !is_newer_timestamp(frame->timestamp(), m_timestamp);
}


Receiver::Receiver() :
  m_frames_num(kStartNumberOfFrames),
  m_num_discarded_packets(0),
  m_num_consecutive_old_packets(0),
  m_num_consecutive_old_frames(0),
  m_drop_count(0)
{
  for (unsigned i = 0; i < kMaxNumberOfFrames; ++i) {
    FrameBuffer *frame = NULL;
    if (i < m_frames_num) {
      frame = new FrameBuffer;
      m_free_frames.push(frame);
    }
    m_frames[i] = frame;
  }
}

Receiver::~Receiver()
{
  for (unsigned i = 0; i < kMaxNumberOfFrames; ++i)
    SAFE_DELETE(m_frames[i]);
}

FrameBufferEnum Receiver::insert_packet(const Packet *pkt,
                                        CompleteFrameProc cb, void *client_data)
{
  uint64_t now = get_time_now();

  FrameBuffer *frame = NULL;
  FrameBufferEnum ret = get_frame(pkt, &frame);
  if (ret != kNoError && !frame)
    return kGeneralError;

  FrameBufferStateEnum prev_stat = frame->get_state();
  bool first = frame->get_high_seq_num() == -1;
  ret = frame->insert_packet(pkt, now);
  FrameBufferEnum buffer_return = ret;
  switch (buffer_return) {
    case kGeneralError:
    case kTimeStampError:
    case kSizeError:
      frame->reset();
      break;
    case kCompleteSession:
      if (is_continuous(frame) && prev_stat != kStateComplete) {
        if (!first)
          m_incomplete_frames.pop_frame(pkt->timestamp());
        m_decodable_frames.insert_frame(frame);
        find_and_insert_continuous_frames(frame);

        uint32_t timestamp = 0;
        bool found_frame = next_complete_timestamp(&timestamp);
        if (!found_frame)
          found_frame = next_maybe_incomplete_timestamp(&timestamp);
        if (!found_frame)
          ret = kNoError;
        else {
          frame = extra_and_set_decode(timestamp);
          if (!frame)
            ret = kNoError;
          else {
            if (cb && cb(client_data, frame) < 0)
              ret = kGeneralError;
            release_frame(frame);
          }
        }
      } else if (first)
        m_incomplete_frames.insert_frame(frame);
      break;
    case kDecodableSession:
    case kIncomplete:
      if (frame->get_state() == kStateEmpty &&
          m_last_decoded_state.update_empty_frame(frame)) {
        frame->reset();
        ret = kNoError;
      } else if (first) {
        ret = kFirstPacket;
        m_incomplete_frames.insert_frame(frame);
      }
      break;
    case kNoError:
    case kDuplicatePacket:
      break;
    case kFlushIndicator:
      ret = kFlushIndicator;
      break;
    default:
      assert("insert_packet(): Undefined value");
  }
  return ret;
}

bool Receiver::is_continuous(const FrameBuffer *frame)
{
  auto_ptr<DecodingState> decoding_state(new DecodingState);
  if (is_continuous_in_state(frame, &m_last_decoded_state)) {
    return true;
  }
  decoding_state->copy_from(m_last_decoded_state);
  for (FrameMap::Iterator it = m_decodable_frames.begin();
       it != m_decodable_frames.end();
       ++it) {
    FrameBuffer *decodable_frame = m_incomplete_frames.frame_at(it);
    if (is_newer_timestamp(decodable_frame->timestamp(), frame->timestamp()))
      break;
    decoding_state->set_state(decodable_frame);
    if (is_continuous_in_state(frame, decoding_state.get())) {
      return true;
    }
  }
  return false;
}

FrameBufferEnum Receiver::get_frame(const Packet *pkt, FrameBuffer **frame)
{
  FrameBufferEnum ret = kNoError;

  *frame = NULL;

  if (m_last_decoded_state.is_old_packet(pkt)) {
    // Account only for media packets
    if (pkt->size_bytes() > 0) {
      ++m_num_discarded_packets;
      ++m_num_consecutive_old_packets;
    }

    // Update last decoded sequence number if the packet arrived late and
    // belongs to a frame with a timestamp equal to the last decoded
    // timestamp.
    m_last_decoded_state.update_old_packet(pkt);

    if (m_num_consecutive_old_packets >= kMaxConsecutiveOldPackets) {
      LOGW("Too many consecutive_old_packets(%u) reached",
           kMaxConsecutiveOldPackets);
      flush();
      return kFlushIndicator;
    }
    return kOldPacket;
  }
  m_num_consecutive_old_packets = 0;

  *frame = m_incomplete_frames.find_frame(pkt->timestamp());
  if (*frame) {
#ifdef XDEBUG
    LOGD("This packet(seq_num=%u, timestamp=%u) belongs to a incomplete frame(%p)",
         pkt->seq_num(), pkt->timestamp(), *frame);
#endif
    return kNoError;
  }
  *frame = m_decodable_frames.find_frame(pkt->timestamp());
  if (*frame) {
#ifdef XDEBUG
    LOGD("This packet(seq_num=%u, timestamp=%u) belongs to a decodable frame(%p)",
         pkt->seq_num(), pkt->timestamp(), *frame);
#endif
    return kNoError;
  }

  // No match, return empty frame.
  *frame = get_empty_frame();
  if (!*frame) {
    LOGW("Unable to get emtpy frame, recycling...");
    bool found_key_frame = recycle_frames_until_key_frame();
    *frame = get_empty_frame();
    if (!*frame)
      return kGeneralError;
    else if (!found_key_frame)
      ret = kFlushIndicator;
  }
  (*frame)->reset();
  return ret;
}

void Receiver::flush()
{
  m_decodable_frames.reset(m_free_frames);
  m_incomplete_frames.reset(m_free_frames);
  m_last_decoded_state.reset();
  m_num_consecutive_old_packets = 0;
  m_num_consecutive_old_frames = 0;
}

FrameBuffer *Receiver::get_empty_frame()
{
  if (!m_free_frames.size()) {
    if (try_to_increase_jitter_buffer_size() < 0)
      return NULL;
  }
  FrameBuffer *frame = NULL;
  m_free_frames.pop(frame);
  return frame;
}

int Receiver::try_to_increase_jitter_buffer_size()
{
  if (m_frames_num >= kMaxNumberOfFrames) {
    LOGE("Max num of frames(%u) reached", kMaxNumberOfFrames);
    return -1;
  }

  FrameBuffer *frame = new FrameBuffer;
  m_frames[m_frames_num++] = frame;
  m_free_frames.push(frame);
  return 0;
}

bool Receiver::recycle_frames_until_key_frame()
{
  bool key_frame_found = false;
  int dropped_frames = 0;

  dropped_frames +=
    m_incomplete_frames.recycle_frames_until_key_frame(key_frame_found, m_free_frames);
  if (!dropped_frames)
    dropped_frames +=
      m_decodable_frames.recycle_frames_until_key_frame(key_frame_found, m_free_frames);
  m_drop_count += dropped_frames;
  m_last_decoded_state.reset();
  return key_frame_found;
}

void Receiver::find_and_insert_continuous_frames(const FrameBuffer *new_frame)
{
  auto_ptr<DecodingState> decoding_state(new DecodingState);
  decoding_state->copy_from(m_last_decoded_state);
  decoding_state->set_state(new_frame);
  for (FrameMap::Iterator it = m_incomplete_frames.begin();
       it != m_incomplete_frames.end();
       ++it) {
    FrameBuffer *frame = m_incomplete_frames.frame_at(it);
    if (!is_newer_timestamp(new_frame->timestamp(), frame->timestamp())) {
      if (is_continuous_in_state(frame, decoding_state.get())) {
        m_decodable_frames.insert_frame(frame);
        m_incomplete_frames.pop_frame(frame->timestamp());
        decoding_state->set_state(frame);
      }
    }
  }
}

bool Receiver::is_continuous_in_state(const FrameBuffer *frame, const DecodingState *ds)
{
  // Is this frame complete or decodable and continuous?
  if (frame->get_state() == kStateComplete &&
      ds->continuous_frame(frame))
    return true;
  return false;
}

void Receiver::cleanup_old_or_empty_frames()
{
  m_drop_count +=
    m_decodable_frames.cleanup_old_or_empty_frames(&m_last_decoded_state, m_free_frames);
  m_drop_count +=
    m_incomplete_frames.cleanup_old_or_empty_frames(&m_last_decoded_state, m_free_frames);
}

bool Receiver::next_complete_timestamp(uint32_t *timestamp)
{
  cleanup_old_or_empty_frames();

  if (m_decodable_frames.empty())
    return false;

  FrameBuffer *frame = m_decodable_frames.frame_at(m_decodable_frames.begin());
  *timestamp = frame->timestamp();
  return true;
}

bool Receiver::next_maybe_incomplete_timestamp(uint32_t *timestamp)
{
  cleanup_old_or_empty_frames();

  FrameBuffer *oldest_frame = next_frame();
  if (!oldest_frame) return false;

  if (m_decodable_frames.empty() &&
      m_incomplete_frames.size() <= 1 &&
      oldest_frame->get_state() == kStateIncomplete)
    return false;

  if (m_last_decoded_state.in_initial_state() &&
      oldest_frame->frame_type() != kFrameKey)
    return false;

  *timestamp = oldest_frame->timestamp();
  return true;
}

FrameBuffer *Receiver::next_frame()
{
  if (!m_decodable_frames.empty())
    return m_decodable_frames.frame_at(m_decodable_frames.begin());
  if (!m_incomplete_frames.empty())
    return m_incomplete_frames.frame_at(m_incomplete_frames.begin());
  return NULL;
}

FrameBuffer *Receiver::extra_and_set_decode(uint32_t timestamp)
{
  bool continuous = true;
  FrameBuffer *frame = m_decodable_frames.pop_frame(timestamp);
  if (!frame) {
    frame = m_incomplete_frames.pop_frame(timestamp);
    if (frame)
      continuous = m_last_decoded_state.continuous_frame(frame);
    else return NULL;
  }
  m_last_decoded_state.set_state(frame);
  return frame;
}

void Receiver::release_frame(FrameBuffer *frame)
{
  m_free_frames.push(frame);
}

}
