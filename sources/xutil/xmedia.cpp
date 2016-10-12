#include "xmedia.h"

#include <cstdlib>

#include "xlog.h"

using namespace xutil;

namespace xmedia {

Frame::Frame() :
  m_dts(-1), m_composition_time(0), m_dat(NULL), m_dat_len(0), m_capacity(0)
{
}

int Frame::make_frame(int32_t ts, byte *dat, uint32_t dat_len,
                      bool reuse_dat, uint32_t composition_time)
{
  if (!reuse_dat) {
    if (m_capacity >= dat_len) {
      // Space is enough to hold this frame's data
      goto copy;
    }

    m_capacity = dat_len + 256;
    BEGIN
    byte *tmp = (byte *) realloc(m_dat, m_capacity);
    if (!tmp) {
      LOGE("realloc for frame's content failed: %s", ERRNOMSG);
      return -1;
    }
    m_dat = tmp;
    END

copy:
    m_dat_len = dat_len;
    memcpy(m_dat, dat, m_dat_len);
  } else {
    if (m_dat)
      LOGW("Previous frame is not cleared, check memory leak");
    m_dat = dat;
    m_capacity = m_dat_len = dat_len;
  }

  m_dts = ts;
  m_composition_time = composition_time;
  return 0;
}

void Frame::clear()
{
  m_dts = -1;
  m_composition_time = 0;
  m_capacity = m_dat_len = 0;
  SAFE_FREE(m_dat);
}

Frame::~Frame()
{
  clear();
}

void print_avc_dcr(const AVCDecorderConfigurationRecord &avc_dcr)
{
  printf("---AVCDecorderConfigurationRecord---\n");
  printf("version: %u\n", avc_dcr.version);
  printf("profile: %u\n", avc_dcr.profile);
  printf("profile_compatibility: %u\n",
         avc_dcr.profile_compatibility);
  printf("level: %u\n", avc_dcr.level);
  printf("length_size_minus_one: %u\n",
         avc_dcr.length_size_minus_one);
  printf("num_of_sps: %u\n", avc_dcr.num_of_sps);
  printf("sps_length: %u\n", avc_dcr.sps_length);
  for (uint16_t idx = 0; idx < avc_dcr.sps_length; ++idx) {
    printf("%02x ", avc_dcr.sps[idx]);
  }
  printf("\nnum_of_pps: %u\n", avc_dcr.num_of_pps);
  printf("pps_length: %u\n", avc_dcr.pps_length);
  for (uint16_t idx = 0; idx < avc_dcr.pps_length; ++idx) {
    printf("%02x ", avc_dcr.pps[idx]);
  }
  printf("\n------------------------------------\n");
}

/////////////////////////////////////////////////////////////

int generate_asc(AudioSpecificConfig &asc,
                 uint8_t profile, uint8_t sample_rate_idx, uint8_t channel)
{
  asc.dat[0] = profile<<3;
  asc.dat[0] |= (sample_rate_idx&0x0E)>>1;
  asc.dat[1] = (sample_rate_idx&0x01)<<7;
  asc.dat[1] |= channel<<3;
  return 0;
}

int parse_asc(const AudioSpecificConfig &asc,
              uint8_t &profile, uint8_t &sample_rate_idx, uint8_t &channel)
{
  return parse_asc(asc.dat, 2, profile, sample_rate_idx, channel);
}
int parse_asc(const uint8_t *buf, int len,
              uint8_t &profile, uint8_t &sample_rate_idx, uint8_t &channel)
{
  /* profile: 5bits
   * samplerateIndex: 4bits
   * channel: 4bits
   * reserved: 3bits */
  profile = (buf[0]&0xf8) >> 3;
  sample_rate_idx = ((buf[0]&0x07) << 1) + ((buf[1]&0x80) >> 7);
  channel = (buf[1]&0x78) >> 3;
  return 0;
}

void print_asc(const AudioSpecificConfig &asc)
{
  uint8_t profile, sample_rate_idx, channel;
  if (parse_asc(asc, profile, sample_rate_idx, channel) < 0) {
    LOGE("Parse AudioSpecificConfig failed");
    return;
  }

  printf("---AudioSpecificConfig---\n");
  printf("%02x %02x\n", asc.dat[0], asc.dat[1]);
  printf("profile: %u (%s)\n",
         profile, audioprof_to_str(profile));
  printf("sample_rate_idx: %u (%sHZ)\n",
         sample_rate_idx, samplerate_idx_to_str(sample_rate_idx));
  printf("channel: %u\n", channel);
  printf("-------------------------\n");
}

int generate_adts_header(const AudioSpecificConfig &asc,
                         uint32_t aac_len, byte adts_hdr[7])
{
  uint8_t profile, sample_rate_idx, channel;

  if (parse_asc(asc, profile, sample_rate_idx, channel) < 0) {
    LOGE("Parse AudioSpecificConfig failed");
    return -1;
  }

  uint32_t aac_frame_len = aac_len + 7;
  adts_hdr[0] = (byte) 0xFF;
  adts_hdr[1] = (byte) 0xF9;
  adts_hdr[2] = (byte) (((profile-1)<<6)+(sample_rate_idx<<2)+(channel>>2));
  adts_hdr[3] = (byte) (((channel&3)<<6)+(aac_frame_len>>11));
  adts_hdr[4] = (byte) ((aac_frame_len&0x7FF) >> 3);
  adts_hdr[5] = (byte) (((aac_frame_len&7)<<5) + 0x1F);
  adts_hdr[6] = (byte) 0xFC;
  return 0;
}

int generate_adts_header(const uint8_t asc_buf[2],
                         uint32_t aac_len, byte adts_hdr[7])
{
  AudioSpecificConfig asc;
  memcpy(asc.dat, asc_buf, 2);
  return generate_adts_header(asc, aac_len, adts_hdr);
}

static struct {
  const char *sprofile;
  int         profile;
} audio_profs[] = {
  { "MAIN"        , 1  },
  { "LC"          , 2  },
  { "SSR"         , 3  },
  { "LTP"         , 4  },
  { "HE_AAC"      , 5  },
  { "ER_LC"       , 17 },
  { "ER_LTP"      , 19 },
  { "LD"          , 23 },
  { "DRM_ER_LC"   , 27 }
};
int str_to_audioprof(const char *str)
{
  for (uint8_t idx=0; idx<NELEM(audio_profs); ++idx) {
    if (!strcasecmp(str, audio_profs[idx].sprofile))
      return audio_profs[idx].profile;
  }

  LOGE("Not supported aac profile %s", str);
  return -1;
}

const char *audioprof_to_str(int aprof)
{
  for (uint8_t idx=0; idx<NELEM(audio_profs); ++idx) {
    if (audio_profs[idx].profile == aprof)
      return audio_profs[idx].sprofile;
  }

  LOGE("Not support aac profile %d", aprof);
  return NULL;
}

static int samplerate[] = {
  96000, 88200, 64000, 48000, 44100, 32000, 24000,
  22050, 16000, 12000, 11025, 8000, 7350, 0, 0, 0 };
int str_to_samplerate_idx(const char *str)
{
  int idx;
  for (idx=0; samplerate[idx]!=atoi(str); ++idx) {
    if (samplerate[idx] == 0) {
      LOGE("Invalid audio sample rate %s", str);
      return -1;
    }
  }
  return idx;;
}

const char *samplerate_idx_to_str(int rate_idx)
{
  static char tmp[6];
  snprintf(tmp, sizeof(tmp), "%d", samplerate[rate_idx]);
  return tmp;
}

static const uint8_t ff_zigzag_direct[64] = {
  0,   1,  8, 16,  9,  2,  3, 10, 
  17, 24, 32, 25, 18, 11,  4,  5, 
  12, 19, 26, 33, 40, 48, 41, 34, 
  27, 20, 13,  6,  7, 14, 21, 28,
  35, 42, 49, 56, 57, 50, 43, 36,
  29, 22, 15, 23, 30, 37, 44, 51,
  58, 59, 52, 45, 38, 31, 39, 46,
  53, 60, 61, 54, 47, 55, 62, 63
};

static const uint8_t zigzag_scan[16+1] = {
  0 + 0 * 4, 1 + 0 * 4, 0 + 1 * 4, 0 + 2 * 4,
  1 + 1 * 4, 2 + 0 * 4, 3 + 0 * 4, 2 + 1 * 4,
  1 + 2 * 4, 0 + 3 * 4, 1 + 3 * 4, 2 + 2 * 4,
  3 + 1 * 4, 3 + 2 * 4, 2 + 3 * 4, 3 + 3 * 4,
};

static void decode_scaling_list(GetBitContext *gb, uint8_t *factors, int size,
                                const uint8_t *jvt_list,
                                const uint8_t *fallback_list)
{   
  int i, last = 8, next = 8;
  const uint8_t *scan = size == 16 ? zigzag_scan : ff_zigzag_direct;
  if (!get_bits1(gb)) // Matrix not written, we use the predicted one
    memcpy(factors, fallback_list, size * sizeof(uint8_t));
  else {
    for (i = 0; i < size; i++) {
      if (next)
        next = (last + get_se_golomb(gb)) & 0xff;
      if (!i && !next) { // Matrix not written, we use the preset one
        memcpy(factors, jvt_list, size * sizeof(uint8_t));
        break;
      }
      last = factors[scan[i]] = next ? next : last;
    }
  }
} 

static const uint8_t default_scaling4[2][16] = {
  {  6, 13, 20, 28, 13, 20, 28, 32,
    20, 28, 32, 37, 28, 32, 37, 42 },
  { 10, 14, 20, 24, 14, 20, 24, 27,
    20, 24, 27, 30, 24, 27, 30, 34 }
};      

static const uint8_t default_scaling8[2][64] = {
  {  6, 10, 13, 16, 18, 23, 25, 27,
    10, 11, 16, 18, 23, 25, 27, 29,
    13, 16, 18, 23, 25, 27, 29, 31,
    16, 18, 23, 25, 27, 29, 31, 33,
    18, 23, 25, 27, 29, 31, 33, 36,
    23, 25, 27, 29, 31, 33, 36, 38,
    25, 27, 29, 31, 33, 36, 38, 40,
    27, 29, 31, 33, 36, 38, 40, 42 },
  {  9, 13, 15, 17, 19, 21, 22, 24,
    13, 13, 17, 19, 21, 22, 24, 25,
    15, 17, 19, 21, 22, 24, 25, 27,
    17, 19, 21, 22, 24, 25, 27, 28,
    19, 21, 22, 24, 25, 27, 28, 30,
    21, 22, 24, 25, 27, 28, 30, 32,
    22, 24, 25, 27, 28, 30, 32, 33,
    24, 25, 27, 28, 30, 32, 33, 35 }
};

static void decode_scaling_matrices(GetBitContext *gb, SPS *sps,
                                    PPS *pps, int is_sps,
                                    uint8_t(*scaling_matrix4)[16],
                                    uint8_t(*scaling_matrix8)[64])
{           
  int fallback_sps = !is_sps && sps->scaling_matrix_present;
  const uint8_t *fallback[4] = {
    fallback_sps ? sps->scaling_matrix4[0] : default_scaling4[0],
    fallback_sps ? sps->scaling_matrix4[3] : default_scaling4[1],
    fallback_sps ? sps->scaling_matrix8[0] : default_scaling8[0],
    fallback_sps ? sps->scaling_matrix8[3] : default_scaling8[1]
  };      
  if (get_bits1(gb)) {
    sps->scaling_matrix_present |= is_sps;
    decode_scaling_list(gb, scaling_matrix4[0], 16, default_scaling4[0], fallback[0]);        // Intra, Y
    decode_scaling_list(gb, scaling_matrix4[1], 16, default_scaling4[0], scaling_matrix4[0]); // Intra, Cr
    decode_scaling_list(gb, scaling_matrix4[2], 16, default_scaling4[0], scaling_matrix4[1]); // Intra, Cb
    decode_scaling_list(gb, scaling_matrix4[3], 16, default_scaling4[1], fallback[1]);        // Inter, Y
    decode_scaling_list(gb, scaling_matrix4[4], 16, default_scaling4[1], scaling_matrix4[3]); // Inter, Cr
    decode_scaling_list(gb, scaling_matrix4[5], 16, default_scaling4[1], scaling_matrix4[4]); // Inter, Cb
    if (is_sps || pps->transform_8x8_mode) {
      decode_scaling_list(gb, scaling_matrix8[0], 64, default_scaling8[0], fallback[2]); // Intra, Y
      decode_scaling_list(gb, scaling_matrix8[3], 64, default_scaling8[1], fallback[3]); // Inter, Y
      if (sps->chroma_format_idc == 3) {
        decode_scaling_list(gb, scaling_matrix8[1], 64, default_scaling8[0], scaling_matrix8[0]); // Intra, Cr
        decode_scaling_list(gb, scaling_matrix8[4], 64, default_scaling8[1], scaling_matrix8[3]); // Inter, Cr
        decode_scaling_list(gb, scaling_matrix8[2], 64, default_scaling8[0], scaling_matrix8[1]); // Intra, Cb
        decode_scaling_list(gb, scaling_matrix8[5], 64, default_scaling8[1], scaling_matrix8[4]); // Inter, Cb
      }
    }
  }
}

static int image_check_size(unsigned int w, unsigned int h)
{
  if ((int)w>0 && (int)h>0 && (w+128)*(uint64_t)(h+128) < INT_MAX/8)
    return 0;

  return -1;
}

#define MAX_SPS_COUNT               32
#define H264_MAX_PICTURE_COUNT      36
#define MAX_LOG2_MAX_FRAME_NUM      (12 + 4)
#define MIN_LOG2_MAX_FRAME_NUM      4
int h264_decode_sps(GetBitContext *gb, SPS *sps)
{
  int profile_idc, level_idc, constraint_set_flags = 0;
  unsigned int sps_id;
  int i, log2_max_frame_num_minus4;

  profile_idc           = get_bits(gb, 8);
  constraint_set_flags |= get_bits1(gb) << 0;   // constraint_set0_flag
  constraint_set_flags |= get_bits1(gb) << 1;   // constraint_set1_flag
  constraint_set_flags |= get_bits1(gb) << 2;   // constraint_set2_flag
  constraint_set_flags |= get_bits1(gb) << 3;   // constraint_set3_flag
  constraint_set_flags |= get_bits1(gb) << 4;   // constraint_set4_flag
  constraint_set_flags |= get_bits1(gb) << 5;   // constraint_set5_flag
  skip_bits(gb, 2);                         // reserved_zero_2bits
  level_idc = get_bits(gb, 8);
  sps_id    = get_ue_golomb_31(gb);

  if (sps_id >= MAX_SPS_COUNT) {
    LOGE("sps_id %u out of range", sps_id);
    return -1;
  }

  sps->sps_id         = sps_id;
  sps->profile_idc    = profile_idc;
  sps->level_idc      = level_idc;

  memset(sps->scaling_matrix4, 16, sizeof(sps->scaling_matrix4));
  memset(sps->scaling_matrix8, 16, sizeof(sps->scaling_matrix8));
  sps->scaling_matrix_present = 0;
  sps->colorspace = 2; //AVCOL_SPC_UNSPECIFIED

  if (sps->profile_idc == 100 ||  // High profile
      sps->profile_idc == 110 ||  // High10 profile
      sps->profile_idc == 122 ||  // High422 profile
      sps->profile_idc == 244 ||  // High444 Predictive profile
      sps->profile_idc ==  44 ||  // Cavlc444 profile
      sps->profile_idc ==  83 ||  // Scalable Constrained High profile (SVC)
      sps->profile_idc ==  86 ||  // Scalable High Intra profile (SVC)
      sps->profile_idc == 118 ||  // Stereo High profile (MVC)
      sps->profile_idc == 128 ||  // Multiview High profile (MVC)
      sps->profile_idc == 138 ||  // Multiview Depth High profile (MVCD)
      sps->profile_idc == 144) {  // old High444 profile
    sps->chroma_format_idc = get_ue_golomb_31(gb);
    if (sps->chroma_format_idc > 3) {
      LOGE("SPS: chroma_format_idc %u not supported",
           sps->chroma_format_idc);
      goto fail;
    } else if (sps->chroma_format_idc == 3) {
      sps->residual_color_transform_flag = get_bits1(gb);
      if (sps->residual_color_transform_flag) {
        LOGE("sps: separate color planes are not supported");
        goto fail;
      }
    }
    sps->bit_depth_luma   = get_ue_golomb(gb) + 8;
    sps->bit_depth_chroma = get_ue_golomb(gb) + 8;
    if (sps->bit_depth_chroma != sps->bit_depth_luma) {
      LOGE("SPS: Different chroma and luma bit depth");
      goto fail;
    }
    if (sps->bit_depth_luma > 14 || sps->bit_depth_chroma > 14) {
      LOGE("SPS: illegal bit depth value (%d, %d)\n",
           sps->bit_depth_luma, sps->bit_depth_chroma);
      goto fail;
    }
    sps->transform_bypass = get_bits1(gb);
    decode_scaling_matrices(gb, sps, NULL, 1,
        sps->scaling_matrix4, sps->scaling_matrix8);
  } else {
    sps->chroma_format_idc = 1;
    sps->bit_depth_luma    = 8;
    sps->bit_depth_chroma  = 8;
  }

  log2_max_frame_num_minus4 = get_ue_golomb(gb);
  if (log2_max_frame_num_minus4 < MIN_LOG2_MAX_FRAME_NUM - 4 ||
      log2_max_frame_num_minus4 > MAX_LOG2_MAX_FRAME_NUM - 4) {
    LOGE("SPS: log2_max_frame_num_minus4 out of range (0-12): %d",
         log2_max_frame_num_minus4);
    goto fail;
  }
  sps->log2_max_frame_num = log2_max_frame_num_minus4 + 4;

  sps->poc_type = get_ue_golomb_31(gb);

  if (sps->poc_type == 0) {
    unsigned t = get_ue_golomb(gb);
    if (t > 12) {
      LOGE("SPS: log2_max_poc_lsb (%d) is out of range", t);
      goto fail;
    }
    sps->log2_max_poc_lsb = t + 4;
  } else if (sps->poc_type == 1) {
    sps->delta_pic_order_always_zero_flag = get_bits1(gb);
    sps->offset_for_non_ref_pic           = get_se_golomb(gb);
    sps->offset_for_top_to_bottom_field   = get_se_golomb(gb);
    sps->poc_cycle_length                 = get_ue_golomb(gb);

    if ((unsigned) sps->poc_cycle_length >=
        NELEM(sps->offset_for_ref_frame)) {
      LOGE("SPS: poc_cycle_length overflow %d", sps->poc_cycle_length);
      goto fail;
    }

    for (i = 0; i < sps->poc_cycle_length; i++)
      sps->offset_for_ref_frame[i] = get_se_golomb(gb);
  } else if (sps->poc_type != 2) {
    LOGE("SPS: illegal POC type %d", sps->poc_type);
    goto fail;
  }

  sps->ref_frame_count = get_ue_golomb_31(gb);
  if (sps->ref_frame_count > H264_MAX_PICTURE_COUNT - 2 ||
      sps->ref_frame_count > 16) {
    LOGE("SPS: too many reference frames %d\n", sps->ref_frame_count);
    goto fail;
  }
  sps->gaps_in_frame_num_allowed_flag = get_bits1(gb);
  sps->mb_width                       = get_ue_golomb(gb) + 1;
  sps->mb_height                      = get_ue_golomb(gb) + 1;
  if ((unsigned)sps->mb_width  >= INT_MAX / 16 ||
      (unsigned)sps->mb_height >= INT_MAX / 16 ||
      image_check_size(16 * sps->mb_width, 16 * sps->mb_height)) {
    LOGE("SPS: mb_width/height overflow");
    goto fail;
  }

  sps->frame_mbs_only_flag = get_bits1(gb);

  // Already parsed what we need, return
  return 0;

fail:
  return -1;
}

void BitrateCalc::check(uint32_t bits, uint32_t interval)
{
  m_bits += bits;

  if (!m_tm_last) {
    m_tm_last = get_time_now();
    return;
  }

  uint64_t now = get_time_now();
  if (now - m_tm_last >= interval) {
    m_bitrate = m_bits*1000.0/(now-m_tm_last);
    m_tm_last = now;
    m_bits = 0;
  }
}

uint32_t BitrateCalc::get_bitrate()
{
  check();
  return m_bitrate/1024;
}

void FPSCalc::check(uint32_t frame_count, uint32_t interval)
{
  m_frame_num += frame_count;

  if (!m_tm_last) {
    m_tm_last = get_time_now();
    return;
  }

  uint64_t now = get_time_now();
  if (now - m_tm_last >= interval) {
    m_fps = m_frame_num*1000.0/(now-m_tm_last);
    m_tm_last = now;
    m_frame_num = 0;
  }
}

float FPSCalc::get_fps()
{
  check(0);
  return m_fps;
}

int is_h264_video(const uint8_t *data, int size)
{
  if (!data || size < 6)
    return -1;

  return STARTCODE4(data) || STARTCODE3(data);
}

int is_h264_key(const uint8_t *data, int size)
{
  if (is_h264_video(data, size)) {
    int nalu_type = data[4]&0x1f;
    if (nalu_type == 9) {
      // Skip NALU_TYPE_AUD and then check again
      nalu_type = data[10]&0x1f;
    }
    return nalu_type == 5 || nalu_type == 7;
  }
  return 0;
}

int is_aac_audio(const uint8_t *data, int size)
{
  if (!data || size < 7)
    return -1;
  return VALUI24(data) == 0xFFFFFF;
}

}
