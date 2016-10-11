#ifndef _MEDIA_PUSHER_H_
#define _MEDIA_PUSHER_H_

#include <string>

#include <xmedia.h>
#include <xfile.h>

#include "common/common.h"
#include "ts/ts_muxer.h"

namespace flvpusher {

class MediaSink;

class MediaPusher {
public:
  MediaPusher(const std::string &input, MediaSink *&sink);
  virtual ~MediaPusher();

  virtual int loop() = 0;

  int dump_video(const std::string &path, bool append = false);
  int dump_audio(const std::string &path, bool append = false);
  int mux2ts(const std::string &tspath);

  virtual int on_frame(const int32_t ts,
                       const byte *dat, const uint32_t dat_len, int is_video,
                       uint32_t composition_time = 0);

protected:
  void set_itime_base(AVRational tb) { m_itime_base = tb; }

  int frame_wait_done(int *timestamp);

protected:
  std::string m_input;
  MediaSink *m_sink;

  xfile::File m_dvf;
  xfile::File m_daf;
  std::string m_tspath;

private:
  AVRational m_itime_base;
  TSMuxer m_tsmuxer;

  xutil::RecursiveMutex m_mutex;

  int m_start_timestamp;
  uint64_t m_start_time;
};

}

#endif /* end of _MEDIA_PUSHER_H_ */
