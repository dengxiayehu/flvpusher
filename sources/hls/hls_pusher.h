#ifndef _HLS_PUSHER_H_
#define _HLS_PUSHER_H_

#include <xconfig.h>
#include <xmedia.h>

#include "common/media_pusher.h"

namespace flvpusher {

class HLSPusher : public MediaPusher {
public:
  HLSPusher(const std::string &input, MediaSink *&sink, xconfig::Config *conf);
  virtual ~HLSPusher();

  virtual int loop();

private:
  enum { AES_SIZE = 16 };
  struct Segment {
    int sequence;
    int duration;
    uint64_t size;

    char *url;
    char *key_path;
    uint8_t aes_key[AES_SIZE];
    bool key_loaded;

    xutil::RecursiveMutex mutex;
    xutil::IOBuffer *iobuf;

    Segment(const int duration, const char *uri);
    Segment(const Segment &obj);
    ~Segment();

    bool is_downloaded();
    bool operator==(const Segment &rhs) const;
    std::string to_string() const;
  };

  struct StreamSys;
  struct HLSStream {
    int id;
    int version;
    int sequence;
    int duration;
    int max_segment_length;
    uint64_t bandwidth;
    uint64_t size;

    std::vector<Segment *> segments;
    char *url;
    xutil::RecursiveMutex mutex;
    bool cache;

    char *current_key_path;
    uint8_t AES_IV[AES_SIZE];
    bool iv_loaded;

    HLSStream(int id, uint64_t bw, const char *url);
    HLSStream(const HLSStream &rhs);
    ~HLSStream();

    void update_stream_size();
    Segment *get_segment(int wanted);
    int get_segment_count() const;
    Segment *find_segment(const int sequence);
    bool operator<(const HLSStream &rhs) const;
    bool operator==(const HLSStream &rhs) const;
    int manage_segment_keys(StreamSys *sys);
    int decode_segment_data(StreamSys *sys, Segment *seg);
    int download_segment_key(StreamSys *sys, Segment *seg);
    int download_segment_data(StreamSys *sys, Segment *seg, int cur_stream);
    int download(StreamSys *sys, Segment *seg);
    std::string to_string() const;
  };

  struct StreamSys {
    xconfig::Config *conf;
    char *m3u8;

    std::vector<HLSStream *> streams;
    uint64_t bandwidth;

    struct hls_download {
      int stream;
      volatile int segment;
      xutil::RecursiveMutex mutex;
      xutil::Condition wait;

      hls_download() : wait(mutex) { }
    } download;

    struct hls_playback {
      int stream;
      volatile int segment;
    } playback;

    struct hls_playlist {
      uint64_t last;
      uint64_t wakeup;
      int tries;
    } playlist;

    bool cache;
    bool meta;
    bool live;
    bool aesmsg;

    xutil::RecursiveMutex mutex;

    DECL_THREAD_ROUTINE(StreamSys, hls_reload_routine);
    xutil::Thread *reload_thrd;
    DECL_THREAD_ROUTINE(StreamSys, hls_routine);
    xutil::Thread *thrd;
    HLSPusher *pusher;

    StreamSys(HLSPusher *pusher_);
    ~StreamSys();

    HLSStream *get_hls(int wanted);
    int get_hls_count() const;
    void start_reload_thread();
    void start_thread();
    int reload_playlist();
    int get_http_live_meta_playlist(std::vector<HLSStream *> &streams);
    int update_playlist(HLSStream *hls_new, HLSStream *hls_old, bool *stream_appended);
    HLSStream *find_hls(HLSStream *hls_new);
  };

private:
  int prepare();
  int live_segment(Segment *seg);

  static int parsed_frame_cb(void *, xmedia::Frame *, int);
  static int read_content_from_url(int timeout, bool verbose, bool trace_ascii,
                                   const char *url, xutil::IOBuffer *iobuf);
  static int read_m3u8_from_url(StreamSys *sys, const char *url, xutil::IOBuffer *iobuf);
  static int parse_m3u8(StreamSys *sys, std::vector<HLSStream *> &streams,
                        uint8_t *buffer, const ssize_t len);
  static int parse_stream_information(StreamSys *sys, std::vector<HLSStream *> &streams,
                                      HLSStream **hls, char *read, const char *uri);
  static char *parse_attributes(const char *line, const char *attr);
  static int parse_target_duration(StreamSys *sys, HLSStream *hls, char *read);
  static int parse_segment_information(HLSStream *hls, char *read, int *duration);
  static int parse_media_sequence(StreamSys *sys, HLSStream *hls, char *read);
  static int parse_key(StreamSys *sys, HLSStream *hls, char *read);
  static int parse_program_date_time(StreamSys *sys, HLSStream *hls, char *read);
  static int parse_allow_cache(StreamSys *sys, HLSStream *hls, char *read);
  static int parse_discontinuity(StreamSys *sys, HLSStream *hls, char *read);
  static int parse_version(StreamSys *sys, HLSStream *hls, char *read);
  static int parse_end_list(StreamSys *sys, HLSStream *hls);
  static int parse_add_segment(HLSStream *hls, const int duration, const char *uri);
  static char *read_line(uint8_t *buffer, uint8_t **pos, const size_t len);
  static char *relative_uri(const char *url, const char *path);
  static int string_to_iv(char *string_hexa, uint8_t iv[AES_SIZE]);
  static int choose_segment(StreamSys *sys, const int current);
  static int prefetch(StreamSys *sys, int current);
  static bool compare_streams(const void* a, const void* b);

private:
  xconfig::Config *m_conf;
  StreamSys *m_sys;
  xutil::RecursiveMutex m_mutex;
};

}

#endif /* end of _HLS_PUSHER_H_ */
