#ifndef _XMEDIA_H_
#define _XMEDIA_H_

#include <xtype.h>
#include <get_bits.h>

#define AAC_ADTS_HEADER_SIZE 7

// Startcode: |0x00 0x00 0x01|
#define STARTCODE3(nalu) \
  (nalu[0]==0 && nalu[1]==0 && nalu[2]==1)
// Startcode: |0x00 0x00 0x00 0x01|
#define STARTCODE4(nalu) \
  (nalu[0]==0 && nalu[1]==0 && nalu[2]==0 && nalu[3]==1)

namespace xmedia {

const static byte nalu_startcode[] = {0, 0, 0, 1};

class Frame {
public:
  Frame();
  ~Frame();

  int make_frame(int32_t ts, byte *dat, uint32_t dat_len,
                 bool reuse_dat, uint32_t composition_time = 0);
  void clear();
  const int32_t &get_dts() const { return m_dts; }
  const uint32_t &get_composition_time() const { return m_composition_time; }
  byte *get_data() const { return m_dat; }
  const uint32_t &get_data_length() const { return m_dat_len; }
  void set_data(byte *dat) { m_dat = dat; }

private:
  DISALLOW_COPY_AND_ASSIGN(Frame);
  int32_t m_dts;
  uint32_t m_composition_time;
  byte *m_dat;
  uint32_t m_dat_len;
  uint32_t m_capacity;
};

typedef int (* FrameCb) (void *opaque, Frame *f, int is_video);

struct AVCDecorderConfigurationRecord {
  byte version;
  byte profile;
  byte profile_compatibility;
  byte level;
  byte length_size_minus_one : 2;
  byte : 6;
  byte num_of_sps : 5;
  byte : 3;
  uint16_t sps_length;
  byte *sps;
  byte num_of_pps;
  uint16_t pps_length;
  byte *pps;
};

void print_avc_dcr(const AVCDecorderConfigurationRecord &avc_dcr);

struct AudioSpecificConfig {
  byte dat[2];
};
int generate_asc(AudioSpecificConfig &asc,
                 uint8_t profile, uint8_t sample_rate_idx, uint8_t channel);
int parse_asc(const AudioSpecificConfig &asc,
              uint8_t &profile, uint8_t &sample_rate_idx, uint8_t &channel);
int parse_asc(const uint8_t *buf, int len,
              uint8_t &profile, uint8_t &sample_rate_idx, uint8_t &channel);
void print_asc(const AudioSpecificConfig &asc);

int generate_adts_header(const AudioSpecificConfig &asc,
                         uint32_t aac_len, byte adts_hdr[7]);
int generate_adts_header(const uint8_t asc_buf[2],
                         uint32_t aac_len, byte adts_hdr[7]);

int str_to_audioprof(const char *str);
const char *audioprof_to_str(int aprof);
int str_to_samplerate_idx(const char *str);
const char *samplerate_idx_to_str(int rate_idx);

struct SPS {
  unsigned int sps_id;
  int profile_idc;
  int level_idc;
  int chroma_format_idc;
  int residual_color_transform_flag;
  int bit_depth_luma;
  int bit_depth_chroma;
  int transform_bypass;
  uint8_t scaling_matrix4[6][16];
  uint8_t scaling_matrix8[6][64];
  int scaling_matrix_present;
  int colorspace;
  int mb_width;
  int mb_height;
  int frame_mbs_only_flag;
  int log2_max_frame_num;
  int poc_type;
  int log2_max_poc_lsb;
  int delta_pic_order_always_zero_flag;
  int offset_for_non_ref_pic;
  int offset_for_top_to_bottom_field;
  int poc_cycle_length;
  short offset_for_ref_frame[256];
  int ref_frame_count;
  int gaps_in_frame_num_allowed_flag;
};

struct PPS {
  int transform_8x8_mode;
  int OTHER_NOT_SUPPORTED;
};

int h264_decode_sps(xutil::GetBitContext *gb, SPS *sps);

class BitrateCalc {
public:
  BitrateCalc() :
    m_bits(0), m_bitrate(0), m_tm_last(0) { }

  void check(uint32_t bits = 0,
             uint32_t interval = 1000); // 1000ms
  uint32_t get_bitrate();

private:
  uint64_t m_bits;
  uint64_t m_bitrate;
  uint64_t m_tm_last;
};

class FPSCalc {
public:
  FPSCalc() :
    m_frame_num(0), m_fps(0), m_tm_last(0) { }

  void check(uint32_t frame_count = 1,
             uint32_t interval = 1000); // Ditto
  float get_fps();

private:
  uint32_t m_frame_num;
  float m_fps;
  uint64_t m_tm_last;
};

int is_h264_video(const uint8_t *data, int size);
int is_h264_key(const uint8_t *data, int size);
int is_aac_audio(const uint8_t *data, int size);

}

#endif /* end of _XMEDIA_H_ */
