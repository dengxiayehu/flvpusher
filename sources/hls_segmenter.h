#ifndef _HLS_SEGMENTER_H_
#define _HLS_SEGMENTER_H_

#include <xlog.h>
#include <xfile.h>

using namespace xutil;

namespace flvpusher {

class FLVParser;
class MP4Parser;

class HLSSegmenter {
public:
    HLSSegmenter(const std::string &hls_playlist,
                 const int hls_time, const int hls_list_size);
    ~HLSSegmenter();

    int set_file(const std::string &media_file, bool loop);

    int loop();

    void ask2quit();

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
    int create_segment(uint32_t idx);
    const std::string get_seek_filename() const;

private:
    std::string m_hls_playlist; // Convert to abs path if needed
    const int m_hls_time;
    const int m_hls_list_size;

    MediaFormat m_mf;
    xfile::File m_pl_file;
    xfile::File m_seek_file;
    union {
        FLVParser *flv_parser;
        MP4Parser *mp4_parser;
    } u;

    HLSInfo m_info;

    volatile bool m_quit;
};

}

#endif /* end of _HLS_SEGMENTER_H_ */
