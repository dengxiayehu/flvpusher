#ifndef _MP4_PARSER_H_
#define _MP4_PARSER_H_

#include <xutil.h>
#include <ffmpeg.h>

#include "mp4_box.h"

using namespace ffmpeg;

namespace flvpusher {

class MP4Parser {
  friend class HLSSegmenter;
public:
  MP4Parser();
  ~MP4Parser();

  int set_file(const std::string &mp4_file);

  int get_resolution(uint32_t &width, uint32_t &height) const;

  AVRational get_vtime_base() const;

  int process(void *opaque, FrameCb cb);

public:
  struct Track {
    uint32_t track_ID;
    uint32_t timescale;
    bool video_track;
    union {
      avcCBox *avcC;
      esdsBox *esds;
    };
    TimeToSampleBox *stts;
    CompositionOffsetBox *ctts;
    SampleToChunkBox *stsc;
    SampleSizeBox *stsz;
    bool large_offset;
    union {
      ChunkOffsetBox *stco;
      ChunkLargeOffsetBox *co64;
    };
    EditListBox *elst;
    union {
      VisualSampleEntry *avc1;
      mp4aBox *mp4a;
    };
    uint64_t duration;
  };

  enum TrackType {VIDEO, AUDIO, NB_TRACK};
  const Track *get_track(TrackType tt)
  { return &m_track[tt]; }

private:
  struct ReadStatus {
    struct {
      uint32_t cnt;           // Sample count in "stts"
      uint32_t offset;        // Offset in "stts"'s sample_delta
    } stts;
    struct {
      uint32_t cnt;           // Sample count in "ctts"
      uint32_t offset;        // Offset in "ctts"'s sample_offset
    } ctts;
    AVFrac dts;               // Current frame's dts
    uint32_t shift_time;      // Shift added to audio track
    uint32_t sample_idx;      // Sample idx to read
    struct LocateChunkCache {
      uint32_t cached_sample_idx;
      uint32_t cached_entry_idx;
      uint32_t cached_total_samples;
    } lcc;
    off_t sample_offset;
  };

  struct SampleEntry {
    int64_t decode_ts;
    uint32_t composition_time;
    uint32_t sample_idx;
    off_t sample_offset;
    uint32_t sample_sz;

    SampleEntry() { memset(this, 0, sizeof(*this)); }
  };

private:
  int init();
  int init_tracks_from_box(Box *box, Track *&trak);

  static uint32_t chunk_containing_sample(uint32_t sample_idx,
                                          const SampleToChunkBox *stsc, uint32_t &first_sample_in_chunk,
                                          ReadStatus::LocateChunkCache *lcc = NULL);

  static int locate_sample(Track *trak, ReadStatus *rstatus,
                           SampleEntry *sentry);
  static int read_frame(File &file, Track *trak,
                        SampleEntry *sentry, Frame *f);

  static void print_ReadStatus(const ReadStatus &rs);

private:
  xfile::File m_file;
  Box *m_box;
  // We only cover first two tracks, normally video and audio
  // tracks (hope so)
  Track m_track[NB_TRACK];
  ReadStatus m_status[NB_TRACK];
  int m_parsed_track;

  /////////////////////////////////////////////////////////////

private:
  struct MP4Context {
    FormatContext *stream;
  };

private:
  int init_ffmpeg_context();

private:
  static int mp4_init(MP4Context *&mp4, File *file);
  static void mp4_free(MP4Context *&mp4);

  static int mp4_read_packet(FormatContext *s, Packet *pkt);

private:
  static InputFormat mp4_demuxer;

private:
  MP4Context *m_mp4;
};

}

#endif /* end of _MP4_PARSER_H_ */
