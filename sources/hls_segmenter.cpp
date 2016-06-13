#include "hls_segmenter.h"

#include <math.h>
#include <memory>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <xnet.h>

#include "flv_parser.h"
#include "mp4_parser.h"
#include "ts_muxer.h"
#include "hls_common.h"
#include "config.h"

#define SELECT_TIMEOUT      (10*1000*1000) // 10 secs
#define MAX_NTIMEOUT        120

using namespace xnet;
using namespace xutil;
using namespace std;

namespace flvpusher {

HLSSegmenter::HLSInfo::HLSInfo()
{
    number = 1;
    sequence = 0;
    start_pts = -1;
    end_pts = -1;
}

/////////////////////////////////////////////////////////////

HLSSegmenter::HLSSegmenter(const string &hls_playlist,
                           const int hls_time) :
    m_hls_playlist(hls_playlist),
    m_hls_time(hls_time),
    m_mf(UNSUPPORTED),
    m_quit(false)
{
    bzero(&u, sizeof(u));
}

HLSSegmenter::~HLSSegmenter()
{
    if (m_mf == FLV)
        SAFE_DELETE(u.flv_parser);
    else if (m_mf == MP4)
        SAFE_DELETE(u.mp4_parser);
}

int HLSSegmenter::set_file(const string &filename, bool loop)
{
    string dir(dirname_(m_hls_playlist));
    if (!is_dir(dir))
        system_("mkdir -p \"%s\" 2>/dev/null", STR(dir));

    int ret = 0;
    if (end_with(filename, ".mp4")) {
        m_mf = MP4;
        u.mp4_parser = new MP4Parser;
        if (u.mp4_parser->set_file(filename) < 0) {
            LOGE("Load mp4 file \"%s\" failed", STR(filename));
            ret = -1;
            goto out;
        }
        u.mp4_parser->init_ffmpeg_context();
    } else {
        LOGE("Not support file:\"%s\" for hls-segmenter",
             STR(filename));
        ret = -1;
        goto out;
    }
    
    BEGIN
    const char *pattern = "%d.ts";
    int basename_size = strlen(STR(m_hls_playlist)) + strlen(pattern) + 1;
    char buf[PATH_MAX] = {0};
    strncpy(buf, STR(m_hls_playlist), basename_size);
    char *p = strrchr(buf, '.');
    if (p) *p = '\0';
    strncat(buf, pattern, basename_size);
    m_info.basenm = buf;
    END
    
    if (!is_valid_vod_m3u8(m_hls_playlist)) {
        if (!loop) {
            if (create_m3u8(true) < 0) {
                LOGE("Create m3u8 file \"%s\" failed",
                     STR(m_hls_playlist));
                ret = -1;
                goto out;
            }
        } else {
            LOGE("No valid vod m3u8 file \"%s\" exists before loop",
                 STR(m_hls_playlist));
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

int HLSSegmenter::loop()
{
    return 0;
}

void HLSSegmenter::ask2quit()
{
    m_quit = true;
}

int HLSSegmenter::create_m3u8(bool create_ts)
{
    auto_ptr<File> pl_file(new File);
    if (!pl_file->open(STR(m_hls_playlist), "w"))
        return -1;

    auto_ptr<File> seek_file(new File);
    if (!seek_file->open(get_seek_filename(), "wb"))
        return -1;

    if (m_mf == MP4) {
        HLSInfo *info = &m_info;
        Packet pkt1, *pkt = &pkt1;
        AVRational tb = (AVRational) {1, 1000};
        string filename(sprintf_(STR(info->basenm), info->sequence));
        MP4Parser::ReadStatus rs[MP4Parser::NB_TRACK];
        TSMuxer *tsmuxer = NULL;
        if (create_ts) {
            tsmuxer = new TSMuxer;
            tsmuxer->set_file(filename,
                              u.mp4_parser->get_vtime_base());
        }
        memcpy(rs, u.mp4_parser->m_status, sizeof(rs));
        if (!seek_file->write_buffer((uint8_t *) rs, sizeof(rs))) {
            LOGE("Write seek file \"%s\" failed",
                 seek_file->get_path());
            return -1;
        }
        while (!m_quit &&
               !u.mp4_parser->mp4_read_packet(u.mp4_parser->m_mp4->stream, pkt)) {
            if (info->start_pts == -1) {
                info->start_pts = pkt->pts;
                info->end_pts = pkt->pts;
            }
            bool is_video = !check_h264_startcode(pkt);
            bool is_key = !is_video ||
                          ((pkt->data[4]&0x1f) == 5 ||
                           (pkt->data[4]&0x1f) == 7);
            if (is_video)
                info->duration = (double) (pkt->pts-info->end_pts)*tb.num/tb.den;
            int64_t end_pts = m_hls_time * AV_TIME_BASE * info->number;
            if (is_video &&
                is_key &&
                av_compare_ts(pkt->pts - info->start_pts, tb, end_pts, AV_TIME_BASE_Q) >= 0) {
                if (create_ts)
                    SAFE_DELETE(tsmuxer);
                info->segments.push_back((HLSSegment) {filename, info->duration});
                if (!seek_file->write_buffer((uint8_t *) rs, sizeof(rs))) {
                    LOGE("Write seek file \"%s\" failed",
                         seek_file->get_path());
                    return -1;
                }

                ++info->sequence;
                ++info->number;
                info->end_pts = pkt->pts;
                info->duration = 0;

                filename = sprintf_(STR(info->basenm), info->sequence);
                if (create_ts) {
                    tsmuxer = new TSMuxer;
                    tsmuxer->set_file(filename, u.mp4_parser->get_vtime_base());
                }
            }
            if (create_ts)
                tsmuxer->write_frame(pkt->pts, pkt->data, pkt->size, is_video);
            memcpy(rs, u.mp4_parser->m_status, sizeof(rs));
            SAFE_FREE(pkt->data);
        }
        if (create_ts)
            SAFE_DELETE(tsmuxer);
        info->segments.push_back((HLSSegment) {filename, info->duration});

        int target_duration = 0;
        FOR_VECTOR_ITERATOR(HLSSegment, info->segments, it) {
            if (target_duration < it->duration)
                target_duration = ceil(it->duration);
        }
        char buf[2048];
        int n;
        n = snprintf(buf, sizeof(buf)-1,
                     "#EXTM3U\n"
                     "#EXT-X-VERSION:3\n"
                     "#EXT-X-ALLOW-CACHE:NO\n"
                     "#EXT-X-TARGETDURATION:%d\n"
                     "#EXT-X-MEDIA-SEQUENCE:0\n",
                     target_duration);
        pl_file->write_buffer((uint8_t *) buf, n);
        FOR_VECTOR_ITERATOR(HLSSegment, info->segments, it) {
            n = snprintf(buf, sizeof(buf)-1,
                         "#EXTINF:%f,\n"
                         "%s\n",
                         it->duration,
                         STR(basename_(it->filename)));
            pl_file->write_buffer((uint8_t *) buf, n);
        }
        n = snprintf(buf, sizeof(buf)-1, "#EXT-X-ENDLIST");
        pl_file->write_buffer((uint8_t *) buf, n);

    }

    return 0;
}

int HLSSegmenter::create_segment(uint32_t idx)
{
    MP4Parser::ReadStatus rs[MP4Parser::NB_TRACK];

    auto_ptr<File> seek_file(new File);
    if (!seek_file->open(get_seek_filename(), "rb+"))
        return -1;

    if (!seek_file->seek_to(idx * sizeof(rs))) {
        LOGE("idx %d out of range", idx);
        return -1;
    }
    if (!seek_file->read_buffer((uint8_t *) rs, sizeof(rs)))
        return -1;
    memcpy(u.mp4_parser->m_status, rs, sizeof(rs));

    HLSInfo *info = &m_info;
    Packet pkt1, *pkt = &pkt1;
    AVRational tb = (AVRational) {1, 1000};
    string filename(sprintf_(STR(info->basenm), idx));
    if (is_file(filename)) {
        //LOGD("ts file \"%s\" already exists", STR(filename));
        return 0;
    }
    TSMuxer *tsmuxer = new TSMuxer;
    tsmuxer->set_file(filename, u.mp4_parser->get_vtime_base());
    while (!m_quit &&
           !u.mp4_parser->mp4_read_packet(u.mp4_parser->m_mp4->stream, pkt)) {
        if (info->start_pts == -1) {
            info->start_pts = pkt->pts;
            info->end_pts = pkt->pts;
        }
        bool is_video = !check_h264_startcode(pkt);
        bool is_key = !is_video ||
                      ((pkt->data[4]&0x1f) == 5 ||
                       (pkt->data[4]&0x1f) == 7);
        if (is_video)
            info->duration = (double) (pkt->pts-info->end_pts)*tb.num/tb.den;
        int64_t end_pts = m_hls_time * AV_TIME_BASE * (idx + 1);
        if (is_video &&
            is_key &&
            av_compare_ts(pkt->pts - info->start_pts, tb, end_pts, AV_TIME_BASE_Q) >= 0) {
            SAFE_FREE(pkt->data);
            break;
        }
        tsmuxer->write_frame(pkt->pts, pkt->data, pkt->size, is_video);
        SAFE_FREE(pkt->data);
    }
    SAFE_DELETE(tsmuxer);
    return 0;
}

const std::string HLSSegmenter::get_seek_filename() const
{
    return sprintf_("%s/%s.seek",
                    STR(dirname_(m_hls_playlist)), STR(basename_(m_hls_playlist)));
}

}
