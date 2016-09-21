#ifndef _TS_PUSHER_H_
#define _TS_PUSHER_H_

#include <xmedia.h>

#include "common/media_pusher.h"

namespace flvpusher {

class TSParser;

class TSPusher : public MediaPusher {
public:
  TSPusher(const std::string &input, MediaSink *&sink, bool hls_segment = false);
  virtual ~TSPusher();

  virtual int loop();

  virtual void ask2quit();

  // Init parser in advance, this function is also called by loop()
  int init_parser();

  TSParser *get_parser() const;

  void set_timestamp_offset(int tm_offset);

private:
  static int parsed_frame_cb(void *, xmedia::Frame *, int);

  int prepare();

  int send_metadata();

private:
  TSParser *m_parser;

  int32_t m_prev_ts;
  uint64_t m_tm_start;
  int m_tm_offset;

  uint32_t m_width;
  uint32_t m_height;

  bool m_hls_segment;
};

}

#endif /* end of _TS_PUSHER_H_ */
