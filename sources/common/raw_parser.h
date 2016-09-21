#ifndef _RAW_PARSER_H_
#define _RAW_PARSER_H_

#include <xutil.h>

#include "common.h"

namespace flvpusher {

class RawParserBase {
public:
  RawParserBase();
  virtual ~RawParserBase() = 0;

  virtual int process(byte *dat, uint32_t len) = 0;

protected:
  xutil::MemHolder m_mem_holder;
  uint32_t m_raw_len;
};

/////////////////////////////////////////////////////////////

class VideoRawParser : public RawParserBase {
public:
  VideoRawParser();
  virtual ~VideoRawParser();

  virtual int process(byte *dat, uint32_t len);

  uint32_t get_nalu_num() const { return m_nalus.size(); }
  const byte *get_nalu_data(uint32_t idx) const;
  uint32_t get_nalu_length(uint32_t idx) const;

  const byte *get_sps() const { return m_sps; }
  uint32_t get_sps_length() const { return m_sps_len; }
  const byte *get_pps() const { return m_pps; }
  uint32_t get_pps_length() const { return m_pps_len; }

  bool is_key_frame() const { return m_key_frame; }

  bool sps_pps_changed() { return m_sps_pps_changed; }

private:
  void reset();

private:
  std::vector<NaluItem *> m_nalus;

  byte m_sps[128];
  uint32_t m_sps_len;
  byte m_pps[128];
  uint32_t m_pps_len;

  bool m_key_frame;

  bool m_sps_pps_changed;
};

/////////////////////////////////////////////////////////////

class AudioRawParser : public RawParserBase {
public:
  virtual int process(byte *dat, uint32_t len);

  const byte *get_asc() const { return m_asc; }

private:
  static void adts_header2asc(
      const byte adts_header[7], byte asc[2]);

private:
  byte m_asc[2];  // AudioSpecificConfig
};

}

#endif /* end of _RAW_PARSER_H_ */
