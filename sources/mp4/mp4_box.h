#ifndef _MP4_BOX_H_
#define _MP4_BOX_H_

#include <xutil.h>
#include <xmedia.h>
#include <xfile.h>

#define MKTAG4(a, b, c, d) ((((uint8_t) (a))<<24) | (((uint8_t) (b))<<16) | \
                            (((uint8_t) (c))<<8)  |  ((uint8_t) (d)))

using namespace xutil;
using namespace xmedia;
using namespace xfile;

namespace flvpusher {

class Box {
public:
  Box(uint32_t _sz, uint32_t _typ, uint64_t _largesz = 0);
  virtual ~Box() { }
  uint64_t getsz() const;
  virtual int init(File *f);
  virtual void print() const;
  void lnk_next(Box *box);

  static int parse_box(Box *&pb, File *f, off_t curend = -1/*cursor-end*/);
  static int free_box(Box *&pb);
  static const char *typ_str(uint32_t typ);

  uint32_t sz;
  uint32_t typ;
  uint64_t largesz;
  Box *next;
  Box *sub;
};

class FullBox : public Box {
public:
  FullBox(uint32_t _sz, uint32_t _typ,
          uint8_t _ver, const uint24_t &_flgs);
  virtual ~FullBox() { }
  virtual int init(File *f);
  virtual void print() const;

  uint8_t ver;
  uint24_t flgs;
};

class FileTypeBox : public Box {
public:
  FileTypeBox(uint32_t _sz, uint32_t _typ);
  int init(File *f);

  uint32_t major_brand;
  uint32_t minor_brand;
  std::vector<uint32_t> compatible_brands;
};

class MediaDataBox : public Box {
public:
  MediaDataBox(uint32_t _sz, uint32_t _typ, uint64_t _largesz);
  int init(File *f);
};

class MovieBox : public Box {
public:
  MovieBox(uint32_t _sz, uint32_t _typ);
  int init(File *f);
};

class MovieHeaderBox : public FullBox {
public:
  MovieHeaderBox(uint32_t _sz, uint32_t _typ,
                 uint8_t _ver, const uint24_t &_flgs);
  int init(File *f);

  union {
    uint32_t u32;
    uint64_t u64;
  } creation_time;
  union {
    uint32_t u32;
    uint64_t u64;
  } modification_time;
  uint32_t timescale;
  union {
    uint32_t u32;
    uint64_t u64;
  } duration;
  int32_t rate;
  int16_t volume;
  uint16_t reserved16;
  uint32_t reserved32[2];
  int32_t matrix[9];
  uint32_t pre_defined[6];
  uint32_t next_track_ID;
};

class TrackBox : public Box {
public:
  TrackBox(uint32_t _sz, uint32_t _typ);
  int init(File *f);
};

class TrackHeaderBox : public FullBox {
public:
  TrackHeaderBox(uint32_t _sz, uint32_t _typ,
                 uint8_t _ver, const uint24_t &_flgs);
  int init(File *f);

  union {
    uint32_t u32;
    uint64_t u64;
  } creation_time;
  union {
    uint32_t u32;
    uint64_t u64;
  } modification_time;
  uint32_t track_ID;
  uint32_t reserved0;
  union {
    uint32_t u32;
    uint64_t u64;
  } duration;
  uint32_t reserved1[2];
  int16_t layer;
  int16_t alternate_group;
  int16_t volume;
  uint16_t reserved2;
  int32_t matrix[9];
  uint32_t width;
  uint32_t height;
};

class MediaBox : public Box {
public:
  MediaBox(uint32_t _sz, uint32_t _typ);
  int init(File *f);
};

class MediaHeaderBox : public FullBox {
public:
  MediaHeaderBox(uint32_t _sz, uint32_t _typ,
                 uint8_t _ver, const uint24_t &_flgs);
  int init(File *f);

  union {
    uint32_t u32;
    uint64_t u64;
  } creation_time;
  union {
    uint32_t u32;
    uint64_t u64;
  } modification_time;
  uint32_t timescale;
  union {
    uint32_t u32;
    uint64_t u64;
  } duration;
  byte pad;
  byte language[3];
  uint16_t pre_defined;
};

class HandlerBox : public Box {
public:
  HandlerBox(uint32_t _sz, uint32_t _typ);
  int init(File *f);

  uint32_t pre_defined;
  uint32_t handler_type;
  uint32_t reserved[3];
  std::string name;
};

class MediaInformationBox : public Box {
public:
  MediaInformationBox(uint32_t _sz, uint32_t _typ);
  int init(File *f);
};

class VideoMediaHeaderBox : public FullBox {
public:
  VideoMediaHeaderBox(uint32_t _sz, uint32_t _typ,
                      uint8_t _ver, const uint24_t &_flgs);
  int init(File *f);

  uint16_t graphicsmode;
  uint16_t opcolor[3];
};

class SoundMediaHeaderBox : public FullBox {
public:
  SoundMediaHeaderBox(uint32_t _sz, uint32_t _typ,
                      uint8_t _ver, const uint24_t &_flgs);
  int init(File *f);

  int16_t balance;
  uint16_t reserved;
};

class DataInformationBox : public Box {
public:
  DataInformationBox(uint32_t _sz, uint32_t _typ);
  int init(File *f);
};

class DataReferenceBox : public FullBox {
public:
  DataReferenceBox(uint32_t _sz, uint32_t _typ,
                   uint8_t _ver, const uint24_t &_flgs);
  int init(File *f);

  uint32_t entry_count;
};

class DataEntryUrlBox : public FullBox {
public:
  DataEntryUrlBox(uint32_t _sz, uint32_t _typ,
                  uint8_t _ver, const uint24_t &_flgs);
  int init(File *f);

  std::string location;
};

class DataEntryUrnBox : public FullBox {
public:
  DataEntryUrnBox(uint32_t _sz, uint32_t _typ,
                  uint8_t _ver, const uint24_t &_flgs);
  int init(File *f);

  std::string name;
  std::string location;
};

class SampleTableBox : public Box {
public:
  SampleTableBox(uint32_t _sz, uint32_t _typ);
  int init(File *f);
};

class SampleEntry;
class SampleDescriptionBox : public FullBox {
public:
  SampleDescriptionBox(uint32_t _sz, uint32_t _typ,
                       uint8_t _ver, const uint24_t &_flgs);
  virtual ~SampleDescriptionBox();
  int init(File *f);

  uint32_t entry_count;
  SampleEntry **elem;
};

class SampleEntry : public Box {
public:
  SampleEntry(uint32_t _sz, uint32_t _typ);
  int init(File *f);

  uint8_t reserved[6];
  uint16_t data_reference_index;
};

class VisualSampleEntry : public SampleEntry {
public:
  VisualSampleEntry(uint32_t _sz, uint32_t _typ);
  int init(File *f);

  uint16_t pre_defined;
  uint16_t reserved1;
  uint32_t pre_defined1[3];
  uint16_t width;
  uint16_t height;
  uint32_t horizresolution;
  uint32_t vertresolution;
  uint32_t reserved2;
  uint16_t frame_count;
  char    compressorname[32];
  uint16_t depth;
  int16_t pre_defined2;
};

class avcCBox : public Box {
public:
  avcCBox(uint32_t _sz, uint32_t _typ);
  virtual ~avcCBox();
  int init(File *f);

  AVCDecorderConfigurationRecord avc_dcr;
};

class TimeToSampleBox : public FullBox {
public:
  TimeToSampleBox(uint32_t _sz, uint32_t _typ,
                  uint8_t _ver, const uint24_t &_flgs);
  virtual ~TimeToSampleBox();
  int init(File *f);

  uint32_t entry_count;
  uint32_t *sample_count;
  uint32_t *sample_delta;
};

class CompositionOffsetBox : public FullBox {
public:
  CompositionOffsetBox(uint32_t _sz, uint32_t _typ,
                       uint8_t _ver, const uint24_t &_flgs);
  virtual ~CompositionOffsetBox();
  int init(File *f);

  uint32_t entry_count;
  uint32_t *sample_count;
  uint32_t *sample_offset; // Always unsigned int(32) for sample_offset
};

class SyncSampleBox : public FullBox {
public:
  SyncSampleBox(uint32_t _sz, uint32_t _typ,
                uint8_t _ver, const uint24_t &_flgs);
  virtual ~SyncSampleBox();
  int init(File *f);

  uint32_t entry_count;
  uint32_t *sample_number;
};

class SampleToChunkBox : public FullBox {
public:
  SampleToChunkBox(uint32_t _sz, uint32_t _typ,
                   uint8_t _ver, const uint24_t &_flgs);
  virtual ~SampleToChunkBox();
  int init(File *f);

  uint32_t entry_count;
  uint32_t *first_chunk;
  uint32_t *sample_per_chunk;
  uint32_t *sample_description_index;
};

class SampleSizeBox : public FullBox {
public:
  SampleSizeBox(uint32_t _sz, uint32_t _typ,
                uint8_t _ver, const uint24_t &_flgs);
  virtual ~SampleSizeBox();
  int init(File *f);

  uint32_t sample_size;
  uint32_t sample_count;
  uint32_t *entry_size;
};

class ChunkOffsetBox : public FullBox {
public:
  ChunkOffsetBox(uint32_t _sz, uint32_t _typ,
                 uint8_t _ver, const uint24_t &_flgs);
  virtual ~ChunkOffsetBox();
  int init(File *f);

  uint32_t entry_count;
  uint32_t *chunk_offset;
};

class ChunkLargeOffsetBox : public FullBox {
public:
  ChunkLargeOffsetBox(uint32_t _sz, uint32_t _typ,
                      uint8_t _ver, const uint24_t &_flgs);
  virtual ~ChunkLargeOffsetBox();
  int init(File *f);

  uint32_t entry_count;
  uint64_t *chunk_offset;
};

class mp4aBox : public Box {
public:
  mp4aBox(uint32_t _sz, uint32_t _typ);
  int init(File *f);

  uint8_t reserved[6];
  uint16_t data_reference_index;
  uint32_t reserved1[2];
  uint16_t channelcount;
  uint16_t samplesize;
  uint16_t pre_defined;
  uint16_t reserved2;
  uint32_t samplerate;
};

class esdsBox : public FullBox {
public:
  esdsBox(uint32_t _sz, uint32_t _typ,
          uint8_t _ver, const uint24_t &_flgs);
  int init(File *f);

  AudioSpecificConfig asc;
  bool to_confirm;
  uint8_t audio_object_type;
  uint32_t samplerate_idx;
  uint8_t channel;
};

class EditBox : public Box {
public:
  EditBox(uint32_t _sz, uint32_t _typ);
  int init(File *f);
};

class EditListBox : public FullBox {
public:
  EditListBox(uint32_t _sz, uint32_t _typ,
              uint8_t _ver, const uint24_t &_flgs);
  int init(File *f);
  virtual ~EditListBox();

  uint32_t entry_count;
  struct ELSTEntry {
    union {
      uint32_t u32;
      uint64_t u64;
    } segment_duration;
    union {
      int32_t i32;
      int64_t i64;
    } media_time;
    int16_t media_rate_integer;
    int16_t media_rate_fraction;
  } *elst_entry;
};

}

#endif /* end of _MP4_BOX_H_ */
