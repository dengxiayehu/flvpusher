#include <math.h>
#include <memory>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include "hls_segmenter.h"
#include "flv/flv_parser.h"
#include "flv/tag_streamer.h"
#include "mp4/mp4_parser.h"
#include "ts/ts_muxer.h"
#include "hls_common.h"
#include "common/config.h"

using namespace xutil;
using namespace std;

#define HLS_URI_SEPERATOR "_dxyh_"
#define SEGMENT_TEMPNAME_SUFFIX ".flvpusher"

namespace flvpusher {

HLSSegmenter::HLSInfo::HLSInfo()
{
  number = 1;
  sequence = 0;
  start_pts = 0;
  end_pts = 0;
}

/////////////////////////////////////////////////////////////

HLSSegmenter::HLSSegmenter(const string &hls_playlist,
                           const int hls_time) :
  m_hls_playlist(hls_playlist),
  m_hls_time(hls_time),
  m_mf(UNSUPPORTED)
{
  bzero(&u, sizeof(u));
}

HLSSegmenter::~HLSSegmenter()
{
  if (m_mf == FLV) {
    SAFE_DELETE(u.flv.parser);
    SAFE_DELETE(u.flv.vstrmer);
    SAFE_DELETE(u.flv.astrmer);
  } else if (m_mf == MP4) {
    SAFE_DELETE(u.mp4.parser);
  }
}

int HLSSegmenter::set_file(const string &filename, bool loop)
{
  string dir(dirname_(m_hls_playlist));
  if (!is_dir(dir))
    system_("mkdir -p \"%s\" 2>/dev/null", STR(dir));

  int ret = 0;
  if (end_with(filename, ".mp4") ||
      end_with(filename, ".3gp") || end_with(filename, ".3gpp")) {
    m_mf = MP4;
    u.mp4.parser = new MP4Parser;
    if (u.mp4.parser->set_file(filename) < 0) {
      LOGE("Load file \"%s\" failed", STR(filename));
      ret = -1;
      goto out;
    }
    u.mp4.parser->init_ffmpeg_context();
  } else if (end_with(filename, ".flv")) {
    m_mf = FLV;
    u.flv.parser = new FLVParser;
    if (u.flv.parser->set_file(filename) < 0) {
      LOGE("Load file \"%s\" failed", STR(filename));
      ret = -1;
      goto out;
    }
    u.flv.vstrmer = new VideoTagStreamer;
    u.flv.astrmer = new AudioTagStreamer;
  } else {
    LOGE("Not support file:\"%s\" for hls-segmenter",
         STR(filename));
    ret = -1;
    goto out;
  }

  BEGIN
  const char *pattern = HLS_URI_SEPERATOR "%d.ts";
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
      auto_ptr<File> info_file(new File);
      if (!info_file->open(sprintf_("%s%c%s", STR(dirname_(m_hls_playlist)),
                           DIRSEP, DEFAULT_HLS_INFO_FILE), "wb"))
        return -1;

      char abs_filename[1024] = { 0 };
      ABS_PATH(STR(filename), abs_filename, sizeof(abs_filename));
      info_file->write_buffer((const uint8_t *) abs_filename, sizeof(abs_filename));
      info_file->writeui8(m_hls_time);
      info_file->writeui64(get_time_now());

      if (create_m3u8() < 0) {
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

int HLSSegmenter::create_m3u8(bool create_ts)
{
  auto_ptr<File> pl_file(new File);
  if (!pl_file->open(STR(m_hls_playlist), "w"))
    return -1;

  auto_ptr<File> seek_file(new File);
  if (!seek_file->open(get_seek_filename(), "wb"))
    return -1;

  HLSInfo *info = &m_info;
  AVRational tb = (AVRational) {1, 1000};
  string filename(sprintf_(STR(info->basenm), info->sequence));
  TSMuxer *tsmuxer = NULL;
  if (m_mf == MP4) {
    Packet pkt1, *pkt = &pkt1;
    MP4Parser::ReadStatus rs[MP4Parser::NB_TRACK];
    if (create_ts) {
      tsmuxer = new TSMuxer;
      tsmuxer->set_file(filename, u.mp4.parser->get_vtime_base());
    }
    memcpy(rs, u.mp4.parser->m_status, sizeof(rs));
    if (!seek_file->write_buffer((uint8_t *) rs, sizeof(rs))) {
      LOGE("Write seek file \"%s\" failed",
           seek_file->get_path());
      return -1;
    }
    while (!interrupt_cb() &&
           !u.mp4.parser->mp4_read_packet(u.mp4.parser->m_mp4->stream, pkt)) {
      int is_video = is_h264_video(pkt->data, pkt->size);
      int is_key = is_h264_key(pkt->data, pkt->size) ||
                   is_aac_audio(pkt->data, pkt->size);
      if (is_video)
        info->duration = (double) (pkt->pts-info->end_pts)*tb.num/tb.den;
      int64_t end_pts = m_hls_time * (int64_t) AV_TIME_BASE * info->number;
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
          tsmuxer->set_file(filename, u.mp4.parser->get_vtime_base());
        }
      }
      if (create_ts)
        tsmuxer->write_frame(pkt->dts, pkt->data, pkt->size, is_video,
                             pkt->pts - pkt->dts);
      memcpy(rs, u.mp4.parser->m_status, sizeof(rs));
      SAFE_FREE(pkt->data);
    }
    if (create_ts)
      SAFE_DELETE(tsmuxer);
    info->segments.push_back((HLSSegment) {filename, info->duration});
  } else if (m_mf == FLV) {
    VideoTagStreamer *vstrmer = u.flv.vstrmer;
    AudioTagStreamer *astrmer = u.flv.astrmer;
    FLVParser::ReadStatus rs[1];
    if (create_ts) {
      tsmuxer = new TSMuxer;
      tsmuxer->set_file(filename, (AVRational) {1001, 30000});
    }
    while (!interrupt_cb() && !u.flv.parser->eof()) {
      FLVParser::FLVTag *tag = u.flv.parser->alloc_tag();
      if (u.flv.parser->read_tag(tag) < 0) {
        if (tag->hdr.typ == FLVParser::TAG_SCRIPT) {
          u.flv.parser->free_tag(tag);
          continue;
        }

        u.flv.parser->free_tag(tag);
        break;
      }

      int32_t pkt_dts =
        (tag->hdr.timestamp_ext<<24) + VALUI24(tag->hdr.timestamp);
      int32_t pkt_pts = pkt_dts;
      byte *pkt_data;
      uint32_t pkt_size;
      int is_video = 1;

      switch (tag->hdr.typ) {
        case FLVParser::TAG_VIDEO:
          vstrmer->process(*tag);
          if (vstrmer->get_strm_length() == 0) {
            goto done;
          }
          pkt_pts += VALUI24(tag->dat.video.pkt.composition_time);
          pkt_data = vstrmer->get_strm();
          pkt_size = vstrmer->get_strm_length();
          break;

        case FLVParser::TAG_AUDIO:
          astrmer->process(*tag);
          if (astrmer->get_strm_length() == 0) {
            goto done;
          }
          is_video = 0;
          pkt_data = astrmer->get_strm();
          pkt_size = astrmer->get_strm_length();
          break;

        case FLVParser::TAG_SCRIPT:
        default:
          goto done;
          break;
      }

      if (!seek_file->size()) {
        seek_file->writeui8(vstrmer->m_sps_len);
        seek_file->write_buffer(vstrmer->m_sps, vstrmer->m_sps_len);
        seek_file->writeui8(vstrmer->m_pps_len);
        seek_file->write_buffer(vstrmer->m_pps, vstrmer->m_pps_len);

        seek_file->write_buffer(astrmer->m_asc.dat, 2);

        memcpy(rs, u.flv.parser->m_status, sizeof(rs));
        if (!seek_file->write_buffer((uint8_t *) rs, sizeof(rs))) {
          LOGE("Write seek file \"%s\" failed",
              seek_file->get_path());
          return -1;
        }
      }

      BEGIN
      bool is_key = is_h264_key(pkt_data, pkt_size) ||
                    is_aac_audio(pkt_data, pkt_size);
      if (is_video)
        info->duration = (double) (pkt_pts-info->end_pts)*tb.num/tb.den;
      int64_t end_pts = m_hls_time * (int64_t) AV_TIME_BASE * info->number;
      if (is_video &&
          is_key &&
          av_compare_ts(pkt_pts - info->start_pts, tb, end_pts, AV_TIME_BASE_Q) >= 0) {
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
        info->end_pts = pkt_pts;
        info->duration = 0;

        filename = sprintf_(STR(info->basenm), info->sequence);
        if (create_ts) {
          tsmuxer = new TSMuxer;
          tsmuxer->set_file(filename, (AVRational) {1001, 30000});
        }
      }
      if (create_ts)
        tsmuxer->write_frame(pkt_dts, pkt_data, pkt_size, is_video,
                             pkt_pts - pkt_dts);
      memcpy(rs, u.flv.parser->m_status, sizeof(rs));
      END
done:
      u.flv.parser->free_tag(tag);
    }
    if (create_ts)
      SAFE_DELETE(tsmuxer);
    info->segments.push_back((HLSSegment) {filename, info->duration});
  }

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
  return 0;
}

int HLSSegmenter::create_segment(uint32_t idx)
{
  auto_ptr<File> seek_file(new File);
  if (!seek_file->open(get_seek_filename(), "rb"))
    return -1;

  HLSInfo *info = &m_info;
  AVRational tb = (AVRational) {1, 1000};
  TSMuxer *tsmuxer = new TSMuxer;
  bool got_frame = false;
  string segment_path(sprintf_(STR(info->basenm), idx));
  // Mux data with this tempname, then |rename| it to segment_path
  string segment_tmp(segment_path + SEGMENT_TEMPNAME_SUFFIX);
  if (m_mf == MP4) {
    MP4Parser::ReadStatus rs[MP4Parser::NB_TRACK];

    if (!seek_file->seek_to(idx * sizeof(rs))) {
      LOGE("idx %d out of range", idx);
      return -1;
    }
    if (!seek_file->read_buffer((uint8_t *) rs, sizeof(rs)))
      return -1;
    memcpy(u.mp4.parser->m_status, rs, sizeof(rs));

    Packet pkt1, *pkt = &pkt1;
    tsmuxer->set_file(segment_tmp, u.mp4.parser->get_vtime_base());
    while (!interrupt_cb() &&
           !u.mp4.parser->mp4_read_packet(u.mp4.parser->m_mp4->stream, pkt)) {
      int is_video = is_h264_video(pkt->data, pkt->size);
      int is_key = is_h264_key(pkt->data, pkt->size) ||
                   is_aac_audio(pkt->data, pkt->size);
      if (is_video)
        info->duration = (double) (pkt->pts-info->end_pts)*tb.num/tb.den;
      int64_t end_pts = m_hls_time * (int64_t) AV_TIME_BASE * (idx + 1);
      if (is_video &&
          is_key &&
          av_compare_ts(pkt->pts - info->start_pts, tb, end_pts, AV_TIME_BASE_Q) >= 0 &&
          got_frame) {
        SAFE_FREE(pkt->data);
        break;
      }
      got_frame = true;
      tsmuxer->write_frame(pkt->dts, pkt->data, pkt->size, is_video,
                           pkt->pts - pkt->dts);
      SAFE_FREE(pkt->data);
    }
  } else if (m_mf == FLV) {
    FLVParser::ReadStatus rs[1];
    VideoTagStreamer *vstrmer = u.flv.vstrmer;
    AudioTagStreamer *astrmer = u.flv.astrmer;

    seek_file->readui8((uint8_t *) &vstrmer->m_sps_len);
    seek_file->read_buffer(vstrmer->m_sps, vstrmer->m_sps_len);
    seek_file->readui8((uint8_t *) &vstrmer->m_pps_len);
    seek_file->read_buffer(vstrmer->m_pps, vstrmer->m_pps_len);

    seek_file->read_buffer(astrmer->m_asc.dat, 2);

    if (!seek_file->seek_ahead(idx * sizeof(rs))) {
      LOGE("idx %d out of range", idx);
      return -1;
    }
    if (!seek_file->read_buffer((uint8_t *) rs, sizeof(rs)))
      return -1;
    u.flv.parser->m_file.seek_to(rs[0].file_offset);

    tsmuxer->set_file(segment_tmp, (AVRational) {1001, 30000});

    while (!interrupt_cb() && !u.flv.parser->eof()) {
      FLVParser::FLVTag *tag = u.flv.parser->alloc_tag();

      if (u.flv.parser->read_tag(tag) < 0) {
        if (tag->hdr.typ == FLVParser::TAG_SCRIPT) {
          u.flv.parser->free_tag(tag);
          continue;
        }

        u.flv.parser->free_tag(tag);
        break;
      }

      int32_t pkt_dts =
        (tag->hdr.timestamp_ext<<24) + VALUI24(tag->hdr.timestamp);
      int32_t pkt_pts = pkt_dts;
      byte *pkt_data;
      uint32_t pkt_size;
      int is_video = 1;

      switch (tag->hdr.typ) {
        case FLVParser::TAG_VIDEO:
          vstrmer->process(*tag);
          if (vstrmer->get_strm_length() == 0) {
            goto done;
          }
          pkt_pts += VALUI24(tag->dat.video.pkt.composition_time);
          pkt_data = vstrmer->get_strm();
          pkt_size = vstrmer->get_strm_length();
          break;

        case FLVParser::TAG_AUDIO:
          astrmer->process(*tag);
          if (astrmer->get_strm_length() == 0) {
            goto done;
          }
          is_video = 0;
          pkt_data = astrmer->get_strm();
          pkt_size = astrmer->get_strm_length();
          break;

        case FLVParser::TAG_SCRIPT:
        default:
          goto done;
          break;
      }

      BEGIN
      bool is_key = is_h264_key(pkt_data, pkt_size) ||
                    is_aac_audio(pkt_data, pkt_size);
      if (is_video)
        info->duration = (double) (pkt_pts-info->end_pts)*tb.num/tb.den;
      int64_t end_pts = m_hls_time * (int64_t) AV_TIME_BASE * (idx + 1);
      if (is_video &&
          is_key &&
          av_compare_ts(pkt_pts - info->start_pts, tb, end_pts, AV_TIME_BASE_Q) >= 0 &&
          got_frame) {
        set_interrupt(true);
        goto done;
      }
      END

      got_frame = true;
      tsmuxer->write_frame(pkt_dts, pkt_data, pkt_size, is_video,
                           pkt_pts - pkt_dts);
done:
      u.flv.parser->free_tag(tag);
    }
  }

  // Do the |rename| now
  int ret = 0;
  if (rename(STR(segment_tmp), STR(segment_path)) != 0) {
    LOGE("Rename segment_tmp \"%s\" to \"%s\" failed: %s",
         STR(segment_tmp), STR(segment_path),
         ERRNOMSG);
    unlink(STR(segment_tmp));
    ret = -1;
  }

  SAFE_DELETE(tsmuxer);
  return ret;
}

const std::string HLSSegmenter::get_seek_filename() const
{
  return sprintf_("%s/%s.seek",
                  STR(dirname_(m_hls_playlist)), STR(basename_(m_hls_playlist)));
}

int HLSSegmenter::create_segment(const std::string &req_segment)
{
  // If requested segment exists, we are done
  if (is_file(req_segment)) {
    return 0;
  }

  string segment_lock_file(
      sprintf_("%s.lock", STR(req_segment)));
  BEGIN
  AutoFileLock _l(segment_lock_file);

  if (!is_file(req_segment)) { // need to check again, if one process already
    // create this segment, we do nothing
    string dir(dirname_(req_segment));
    string hls_info_path(dir + "/hls_info.txt");
    if (!is_file(hls_info_path) && !is_file(req_segment)) {
      LOGE("%s isn't a hls vod dir", STR(dir));
      return -1;
    }

    // Get ts-segment's index
    const char *p = strrchr(STR(req_segment), '.');
    for (char ch = *--p; isdigit(ch); ch = *--p);
    ++p;
    int ts_index = atoi(p);

    // Continue to back-skip HLS_URI_SEPERATOR
    int hls_uri_seperator_len = strlen(HLS_URI_SEPERATOR);
    if (strncmp(p - hls_uri_seperator_len, HLS_URI_SEPERATOR,
                hls_uri_seperator_len) != 0) {
      LOGE("Bad ts_segemnt request \"%s\"", STR(req_segment));
      return -1;
    }
    p -= hls_uri_seperator_len;

    char media_file[1024];
    uint8_t hls_time;

    BEGIN
    File info_file;
    if (!info_file.open(hls_info_path, "rb")) {
      return -1;
    }
    info_file.read_buffer((uint8_t *) media_file, sizeof(media_file));
    info_file.readui8(&hls_time);
    END

    uint64_t generate_start_time = get_time_now();

    auto_ptr<HLSSegmenter> hls_segmenter(
        new HLSSegmenter(sprintf_("%.*s.m3u8",
                                  p-STR(req_segment), STR(req_segment)),
                         hls_time));
    if (hls_segmenter->set_file(media_file) < 0) {
      LOGE("HLSSegmenter load file \"%s\" failed",
           STR(media_file));
      return -1;
    }
    hls_segmenter->create_segment(ts_index);

    LOGD("Generate \"%s\" done (%dms used)",
         STR(req_segment), get_time_now() - generate_start_time);
  }
  END

  unlink(STR(segment_lock_file));
  return 0;
}

int HLSSegmenter::access_m3u8(const std::string &req_m3u8)
{
  string dir(dirname_(req_m3u8));
  string hls_info_path(dir + "/hls_info.txt");
  if (!is_file(hls_info_path) && !is_file(req_m3u8)) {
    LOGE("%s isn't a hls vod dir", STR(dir));
    return -1;
  }

  AutoFileLock _l(hls_info_path);
  File info_file;
  if (!info_file.open(sprintf_("%s%c%s", STR(dir), DIRSEP, DEFAULT_HLS_INFO_FILE),
                      "rb+")) {
    return -1;
  }
  info_file.seek_to(1024 /* filename */ + 1 /* hls_time */);
  info_file.writeui64(get_time_now());
  return 0;
}

}
