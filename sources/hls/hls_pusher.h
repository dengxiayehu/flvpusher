#ifndef _HLS_PUSHER_H_
#define _HLS_PUSHER_H_

#include <xconfig.h>

#include "common/media_pusher.h"

namespace flvpusher {

class TSPusher;

class HLSPusher : public MediaPusher {
public:
    HLSPusher(const std::string &input, MediaSink *&sink, xconfig::Config *conf);
    virtual ~HLSPusher();

    virtual int loop();
    virtual void ask2quit();

private:
    enum { AES_SIZE = 16 };
    struct segment {
        int sequence;
        int duration;
        uint64_t size;

        char *url;
        char *key_path;
        uint8_t aes_key[AES_SIZE];
        bool key_loaded;

        xutil::RecursiveMutex mutex;
        xutil::IOBuffer *iobuf;

        segment(const int duration, const char *uri);
        segment(const segment &obj);
        ~segment();

        bool is_downloaded();
        bool operator==(const segment &rhs) const;
        std::string to_string() const;
    };

    struct stream_sys;
    struct hls_stream {
        int id;
        int version;
        int sequence;
        int duration;
        int max_segment_length;
        uint64_t bandwidth;
        uint64_t size;

        std::vector<segment *> segments;
        char *url;
        xutil::RecursiveMutex mutex;
        bool cache;

        char *current_key_path;
        uint8_t AES_IV[AES_SIZE];
        bool iv_loaded;

        hls_stream(int id, uint64_t bw, const char *url);
        hls_stream(const hls_stream &rhs);
        ~hls_stream();

        void update_stream_size();
        segment *get_segment(int wanted);
        int get_segment_count() const;
        segment *find_segment(const int sequence);
        bool operator<(const hls_stream &rhs) const;
        bool operator==(const hls_stream &rhs) const;
        int manage_segment_keys(stream_sys *sys);
        int decode_segment_data(stream_sys *sys, segment *seg);
        int download_segment_key(stream_sys *sys, segment *seg);
        int download_segment_data(stream_sys *sys, segment *seg, int cur_stream);
        int download(stream_sys *sys, segment *seg);
        std::string to_string() const;
    };

    struct stream_sys {
        xconfig::Config *conf;
        char *m3u8;

        std::vector<hls_stream *> streams;
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

        DECL_THREAD_ROUTINE(stream_sys, hls_reload_routine);
        xutil::Thread *reload_thrd;
        DECL_THREAD_ROUTINE(stream_sys, hls_routine);
        xutil::Thread *thrd;
        HLSPusher *pusher;

        stream_sys(HLSPusher *pusher_);
        ~stream_sys();

        hls_stream *get_hls(int wanted);
        int get_hls_count() const;
        void start_reload_thread();
        void start_thread();
        int reload_playlist();
        int get_http_live_meta_playlist(std::vector<hls_stream *> &streams);
        int update_playlist(hls_stream *hls_new, hls_stream *hls_old, bool *stream_appended);
        hls_stream *find_hls(hls_stream *hls_new);
    };

private:
    int prepare();
    int live_segment(segment *seg);

    static int read_content_from_url(int timeout, bool verbose, bool trace_ascii,
                                     const char *url, xutil::IOBuffer *iobuf);
    static int read_m3u8_from_url(stream_sys *sys, const char *url, xutil::IOBuffer *iobuf);
    static int parse_m3u8(stream_sys *sys, std::vector<hls_stream *> &streams,
                          uint8_t *buffer, const ssize_t len);
    static int parse_stream_information(stream_sys *sys, std::vector<hls_stream *> &streams,
                                        hls_stream **hls, char *read, const char *uri);
    static char *parse_attributes(const char *line, const char *attr);
    static int parse_target_duration(stream_sys *sys, hls_stream *hls, char *read);
    static int parse_segment_information(hls_stream *hls, char *read, int *duration);
    static int parse_media_sequence(stream_sys *sys, hls_stream *hls, char *read);
    static int parse_key(stream_sys *sys, hls_stream *hls, char *read);
    static int parse_program_date_time(stream_sys *sys, hls_stream *hls, char *read);
    static int parse_allow_cache(stream_sys *sys, hls_stream *hls, char *read);
    static int parse_discontinuity(stream_sys *sys, hls_stream *hls, char *read);
    static int parse_version(stream_sys *sys, hls_stream *hls, char *read);
    static int parse_end_list(stream_sys *sys, hls_stream *hls);
    static int parse_add_segment(hls_stream *hls, const int duration, const char *uri);
    static char *read_line(uint8_t *buffer, uint8_t **pos, const size_t len);
    static char *relative_uri(const char *url, const char *path);
    static int string_to_iv(char *string_hexa, uint8_t iv[AES_SIZE]);
    static int choose_segment(stream_sys *sys, const int current);
    static int prefetch(stream_sys *sys, int current);
    static bool compare_streams(const void* a, const void* b);

private:
    xconfig::Config *m_conf;
    stream_sys *m_sys;
    xutil::RecursiveMutex m_mutex;
    TSPusher *m_ts_pusher;
};

}

#endif /* end of _HLS_PUSHER_H_ */
