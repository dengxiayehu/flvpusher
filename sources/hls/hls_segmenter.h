#ifndef _HLS_SEGMENTER_H_
#define _HLS_SEGMENTER_H_

#include <xlog.h>
#include <xfile.h>

using namespace xutil;

namespace flvpusher {

class FLVParser;
class MP4Parser;
class VideoTagStreamer;
class AudioTagStreamer;

class HLSSegmenter {
public:
  HLSSegmenter(const std::string &hls_playlist,
               const int hls_time);
  ~HLSSegmenter();

  int set_file(const std::string &media_file, bool loop = false);
  int create_segment(uint32_t idx);

  int loop();

public:
  static int create_segment(const std::string &req_segment);
  static int access_m3u8(const std::string &req_m3u8);

private:
  enum MediaFormat { UNSUPPORTED, FLV, MP4 };

  struct HLSSegment {
    std::string filename;
    double duration;
  };

  struct HLSInfo {
    unsigned number;
    int64_t sequence;
    std::string basenm;
    int start_pts;
    int end_pts;
    double duration;
    std::vector<HLSSegment> segments;

    HLSInfo();
  };

private:
  int create_m3u8(bool create_ts = false);
  const std::string get_seek_filename() const;

private:
  std::string m_hls_playlist; // Convert to abs path if needed
  const int m_hls_time;

  MediaFormat m_mf;
  union {
    struct {
      FLVParser *parser;
      VideoTagStreamer *vstrmer;
      AudioTagStreamer *astrmer;
    } flv;
    struct {
      MP4Parser *parser;
    } mp4;
  } u;

  HLSInfo m_info;
};

}

#endif /* end of _HLS_SEGMENTER_H_ */
