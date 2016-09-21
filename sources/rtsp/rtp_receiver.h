#ifndef _RTP_RECEIVER_H_
#define _RTP_RECEIVER_H_

#include <xutil.h>
#include <xqueue.h>

#define PAYLOAD_TYPE_RED    116

namespace flvpusher {

#pragma pack(1)
struct RTPHeaderRaw {
  uint16_t cc:4;
  uint16_t x:1;
  uint16_t p:1;
  uint16_t v:2;
  uint16_t pt:7;
  uint16_t m:1;
  uint16_t seq;
  uint32_t ts;
  uint32_t ssrc;
};
#pragma pack()

static const uint8_t kRtpCsrcSize = 15;

static const uint16_t kRtpOneByteHeaderExtensionId = 0xBEDE;

static const size_t  kRtpOneByteHeaderLength = 4;
static const size_t  kTransmissionTimeOffsetLength = 4;
static const size_t  kAudioLevelLength = 2;
static const size_t  kAbsoluteSendTimeLength = 4;

enum RTPExtensionType {
  kRtpExtensionNone,
  kRtpExtensionTransmissionTimeOffset,
  kRtpExtensionAudioLevel,
  kRtpExtensionAbsoluteSendTime
};

struct RTPHeaderExtension {
  int32_t transmission_time_offset;
  uint32_t absolute_send_time;
};

struct RTPHeader {
  bool marker_bit;
  uint8_t payload_type;
  uint16_t sequence_number;
  uint32_t timestamp;
  uint32_t ssrc;
  uint8_t num_CSRCs;
  uint32_t arr_of_CSRCs[kRtpCsrcSize];
  uint8_t padding_length;
  uint16_t header_length;
  RTPHeaderExtension extension;
};

int parse_rtp_header(const uint8_t *pkt, int pkt_len,
                     RTPHeaderRaw **hdr,
                     const uint8_t **payload, unsigned *payload_len,
                     RTPHeader *rtp_header);


enum FrameType {
  kFrameUnknown   = 0,
  kFrameKey       = 1, // Independent frame
  kFrameDelta     = 2, // Depends on the previus frame
};

enum FrameBufferEnum {
  kNotInitialized       = -6,
  kOldPacket            = -5,
  kGeneralError         = -4,
  kFlushIndicator       = -3,   // Indicator that a flush has occurred.
  kTimeStampError       = -2,
  kSizeError            = -1,
  kNoError              = 0,
  kIncomplete           = 1,    // Frame incomplete.
  kFirstPacket          = 2,
  kCompleteSession      = 3,    // at least one layer in the frame complete.
  kDecodableSession     = 4,    // Frame incomplete, but ready to be decoded
  kDuplicatePacket      = 5     // We're receiving a duplicate packet.
};

enum FrameBufferStateEnum {
  kStateEmpty,        // Frame popped by the RTP receiver
  kStateIncomplete,   // Frame that have one or more packet(s) stored
  kStateComplete,     // Frame that have all packets
};

enum {
  kStartNumberOfFrames  = 6,
  kMaxNumberOfFrames    = 100
};

enum {
  kMaxConsecutiveOldPackets   = 300,
  kMaxPacketsInFrame          = 80,
};

class FrameBuffer;

class Packet {
  public: 
    Packet(const uint8_t *ptr, const uint32_t size,
           uint16_t seq_num, uint32_t timestamp, bool marker_bit,
           FrameType ft = kFrameUnknown, bool current_packet_begins_frame = true,
           bool first_packet = false);
    ~Packet();

    void reset();
    const uint8_t *data_ptr() const { return m_data_ptr; }
    const uint32_t size_bytes() const { return m_size_bytes; }
    const uint16_t seq_num() const { return m_seq_num; }
    const uint32_t timestamp() const { return m_timestamp; }
    const bool marker_bit() const { return m_marker_bit; }
    const FrameType &frame_type() const { return m_frame_type; }
    const std::string to_string() const;
    void set_frame_type(const FrameType ft) { m_frame_type = ft; }
    const bool &current_packet_begins_frame() const { return m_current_packet_begins_frame; }
    const bool &first_packet() const { return m_first_packet; }

  private:
    uint8_t *m_data_ptr;
    uint32_t m_size_bytes;
    uint16_t m_seq_num;
    uint32_t m_timestamp;
    bool m_marker_bit;
    FrameType m_frame_type;
    bool m_current_packet_begins_frame;
    bool m_first_packet;
};

typedef std::map<uint16_t , Packet *> PacketList;

class FrameBuffer {
public:
  FrameBuffer();
  ~FrameBuffer();

  const FrameType frame_type() const { return m_frame_type; }
  int get_high_seq_num() const;
  int get_low_seq_num() const;
  void reset();
  FrameBufferStateEnum get_state(uint32_t *timestamp = NULL) const;
  const uint32_t timestamp() const { return m_timestamp; }
  FrameBufferEnum insert_packet(const Packet *pkt, uint64_t now);
  void set_state(FrameBufferStateEnum state);
  const FrameBufferStateEnum get_state() { return m_state; }
  void update_complete_session();
  const bool complete() const { return m_complete; }
  size_t size_bytes() const;
  size_t size() const { return m_packets.size(); }

  typedef PacketList::iterator Iterator;
  Iterator begin() { return m_packets.begin(); }
  Iterator end() { return m_packets.end(); }
  Packet *packet_at(Iterator it) { return MAP_VAL(it); }

private:
  static bool in_sequence(const Packet *pkt, const Packet *prev_pkt);

private:
  PacketList m_packets;
  FrameType m_frame_type;
  int m_empty_seq_num_high;
  int m_empty_seq_num_low;
  uint32_t m_timestamp;
  FrameBufferStateEnum m_state;
  bool m_complete;
};

class DecodingState {
public:
  DecodingState();

  bool is_old_packet(const Packet *pkt);
  void update_old_packet(const Packet *pkt);
  void reset();
  bool update_empty_frame(const FrameBuffer *frame);
  bool continuous_seq_num(uint16_t seq_num) const;
  bool continuous_frame(const FrameBuffer *frame) const;
  void copy_from(const DecodingState &ds);
  void set_state(const FrameBuffer *frame);
  bool is_old_frame(const FrameBuffer *frame) const;
  const bool in_initial_state() const { return m_in_initial_state; }

private:
  uint16_t m_seq_num;
  uint32_t m_timestamp;
  bool m_in_initial_state;
};

typedef xutil::Queue<FrameBuffer *> FrameList;

class FrameMap {
public:
  FrameBuffer *find_frame(uint32_t timestamp);
  void clear() { m_frames.clear(); }
  bool empty() const { return m_frames.empty(); }
  size_t size() const { return m_frames.size(); }
  void reset(FrameList &free_frames);
  int recycle_frames_until_key_frame(bool &key_frame_found, FrameList &free_frames);
  FrameBuffer *pop_frame(uint32_t timestamp);
  void insert_frame(FrameBuffer *frame);
  int cleanup_old_or_empty_frames(DecodingState *ds, FrameList &free_frames);

  typedef std::map<uint32_t, FrameBuffer *>::iterator Iterator;
  Iterator begin() { return m_frames.begin(); }
  Iterator end() { return m_frames.end(); }
  FrameBuffer *frame_at(Iterator it) { return MAP_VAL(it); }

private:
  std::map<uint32_t, FrameBuffer *> m_frames;
};

class Receiver {
public:
  Receiver();
  ~Receiver();

  typedef int CompleteFrameProc(void *client_data, FrameBuffer *frame);
  FrameBufferEnum insert_packet(const Packet *pkt,
      CompleteFrameProc cb, void *client_data);

private:
  FrameBufferEnum get_frame(const Packet *pkt, FrameBuffer **frame);
  void flush();
  FrameBuffer *get_empty_frame();
  int try_to_increase_jitter_buffer_size();
  bool recycle_frames_until_key_frame();
  void find_and_insert_continuous_frames(const FrameBuffer *new_frame);
  bool is_continuous(const FrameBuffer *frame);
  bool is_continuous_in_state(const FrameBuffer *frame, const DecodingState *ds);
  void cleanup_old_or_empty_frames();
  bool next_complete_timestamp(uint32_t *timestamp);
  bool next_maybe_incomplete_timestamp(uint32_t *timestamp);
  FrameBuffer *next_frame();
  FrameBuffer *extra_and_set_decode(uint32_t timestamp);
  void release_frame(FrameBuffer *frame);

private:
  FrameMap m_decodable_frames;
  FrameMap m_incomplete_frames;
  FrameList m_free_frames;
  unsigned m_frames_num;
  FrameBuffer *m_frames[kMaxNumberOfFrames];
  DecodingState m_last_decoded_state;
  unsigned m_num_discarded_packets;
  unsigned m_num_consecutive_old_packets;
  unsigned m_num_consecutive_old_frames;
  unsigned m_drop_count;
};


inline bool is_newer_seq_num(uint16_t seq_num, uint16_t prev_seq_num)
{
  return seq_num != prev_seq_num &&
    (uint16_t)(seq_num - prev_seq_num) < 0x8000;
}

inline bool is_newer_timestamp(uint32_t timestamp, uint32_t prev_timestamp)
{
  return timestamp != prev_timestamp &&
    (uint32_t)(timestamp - prev_timestamp) < 0x80000000;
}

inline uint16_t latest_seq_num(uint16_t seq_num1, uint16_t seq_num2)
{
  return is_newer_seq_num(seq_num1, seq_num2) ?
    seq_num1 : seq_num2;
}

inline uint32_t latest_timestamp(uint32_t timestamp1, uint32_t timestamp2)
{
  return is_newer_timestamp(timestamp1, timestamp2) ? timestamp1 : timestamp2;
}


}

#endif /* end of _RTP_RECEIVER_H_ */
