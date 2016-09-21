#ifndef _XFILE_H_
#define _XFILE_H_

#include "xutil.h"

namespace xfile {

class File {
public:
  File();
  ~File();

  bool open(const std::string &path, const char *mode);
  bool flush();
  void close();

  off_t cursor() const;
  off_t size() const { return m_filesz; }
  const char *get_path() const { return m_path.c_str(); }
  bool eof() const { return !!feof(m_fp); }
  bool is_opened() const { return m_fp != NULL; }

  bool seek_begin() const;
  bool seek_end() const;
  bool seek_ahead(off_t cnt) const;    // cursor move forward
  bool seek_behind(off_t cnt) const;   // cursor move backward
  bool seek_to(off_t pos) const;

  bool readi8(int8_t *val) const;
  bool readi16(int16_t *val, bool net_order = false) const;
  bool readi24(int32_t *val, bool net_order = false) const;
  bool readi32(int32_t *val, bool net_order = false) const;
  bool readi64(int64_t *val, bool net_order = false) const;
  bool readui8(uint8_t *val) const;
  bool readui16(uint16_t *val, bool net_order = false) const;
  bool readui24(uint32_t *val, bool net_order = false) const;
  bool readui32(uint32_t *val, bool net_order = false) const;
  bool readui64(uint64_t *val, bool net_order = false) const;
  bool read_buffer(uint8_t *buf, size_t sz) const;
  bool read_line(char *buf, size_t sz) const;

  bool writei8(int8_t val) const;
  bool writei16(int16_t val, bool net_order = false) const;
  bool writei24(int32_t val, bool net_order = false) const;
  bool writei32(int32_t val, bool net_order = false) const;
  bool writei64(int64_t val, bool net_order = false) const;
  bool writeui8(uint8_t val) const;
  bool writeui16(uint16_t val, bool net_order = false) const;
  bool writeui24(uint32_t val, bool net_order = false) const;
  bool writeui32(uint32_t val, bool net_order = false) const;
  bool writeui64(uint64_t val, bool net_order = false) const;
  bool write_string(const char *val) const;
  bool write_buffer(const uint8_t *buffer, long len) const;

  static std::string read_content(const std::string &path);
  static int flush_content(const std::string &path, const uint8_t *buf, int buf_size, const char *mode = "w");

private:
  FILE           *m_fp;
  mutable off_t   m_filesz;
  std::string     m_path;
};

}

#endif /* end of _XFILE_H_ */
