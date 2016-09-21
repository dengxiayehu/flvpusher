#ifndef _FLV_MUXER_H_
#define _FLV_MUXER_H_

#include <xutil.h>
#include <xfile.h>

namespace flvpusher {

class FLVMuxer {
public:
  FLVMuxer();
  ~FLVMuxer();

  int set_file(const std::string &flvpath);

  bool is_opened() const;

  int write_tag(int typ, int ts, const uint8_t *buf, int buf_size);

  const char *get_path() const;

private:
  xfile::File *m_file;
  int m_tm_offset;
};

}

#endif /* end of _FLV_MUXER_H_ */
