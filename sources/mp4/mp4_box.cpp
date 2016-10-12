#include "mp4_box.h"

#include <cstdlib>

#include <xlog.h>

//#define XDEBUG
//#define XDEBUG_FULL

namespace flvpusher {

Box::Box(uint32_t _sz, uint32_t _typ, uint64_t _largesz) :
  sz(_sz), typ(_typ), largesz(_largesz)
{
  next = NULL;
  sub = NULL;
}

int Box::init(File *f)
{
  LOGW("Shouldn't call Box's init() function");
  return 0;
}

void Box::print() const
{
#ifdef XDEBUG
  printf("============ %s ============\n", typ_str(typ));
  printf("box size: %u\n", sz);
  printf("box type: %s\n", typ_str(typ));
#endif
}

uint64_t Box::getsz() const
{
  return sz == 1 ? largesz : sz;
}

void Box::lnk_next(Box *box)
{
  if (!next)
    next = box;
  else {
    Box *p = next;
    while (p->next)
      p = p->next;
    p->next = box;
  }
}

int Box::parse_box(Box *&pb, File *f, off_t curend)
{
  while (!(f->eof() || f->cursor() >= curend)) {
    // First 4bytes box size(not including sz and typ's size)
    uint32_t sz;
    uint32_t typ = 0;
    uint64_t largesz = 0;
    Box *pcb = NULL; // Pointer to current box
    off_t cursave = f->cursor();

    if (!f->readui32(&sz, true)) {
      LOGE("Read box's size failed");
      return -1;
    }

    // Box type should be 4-chars long
    if (!f->readui32(&typ, true)) {
      LOGE("Read box's type failed");
      goto skip;
    }

    // Figure out whether is largesize box
    if (sz == 1) {
      if (!f->readui64(&largesz, true)) {
        LOGE("Read box's largesize failed");
        goto skip;
      }
    } else if (sz > (f->size() - cursave)) {
      uint32_t sz_adjust = f->size() - cursave;
      LOGW("Box |%s| with too large size(%u), adjust it to %u",
           typ_str(typ), sz, sz_adjust);
      sz = sz_adjust;
    }

    if (curend == -1) { // Parse only one box
      if (sz == 1) {
        curend = cursave + largesz;
      } else if (sz == 0) {
        curend = f->size();
      } else {
        curend = cursave + sz;
      }
    }

#define GET_FULLBOX_VER_FLGS \
    uint8_t ver; \
    uint24_t flgs; \
    if (!f->readui8(&ver)) { \
      LOGE("Read version failed"); \
      goto skip; \
    } \
    if (!f->read_buffer(flgs, sizeof(flgs))) { \
      LOGE("Read flags failed"); \
      goto skip; \
    }

    if (typ == MKTAG4('f', 't', 'y', 'p')) {
      pcb = new FileTypeBox(sz, typ);
    } else if (typ == MKTAG4('m', 'd', 'a', 't')) {
      pcb = new MediaDataBox(sz, typ, largesz);
    } else if (typ == MKTAG4('m', 'o', 'o', 'v')) {
      pcb = new MovieBox(sz, typ);
    } else if (typ == MKTAG4('m', 'v', 'h', 'd')) {
      GET_FULLBOX_VER_FLGS
      pcb = new MovieHeaderBox(sz, typ, ver, flgs);
    } else if (typ == MKTAG4('t', 'r', 'a', 'k')) {
      pcb = new TrackBox(sz, typ);
    } else if (typ == MKTAG4('t', 'k', 'h', 'd')) {
      GET_FULLBOX_VER_FLGS
      pcb = new TrackHeaderBox(sz, typ, ver, flgs);
    } else if (typ == MKTAG4('m', 'd', 'i', 'a')) {
      pcb = new MediaBox(sz, typ);
    } else if (typ == MKTAG4('m', 'd', 'h', 'd')) {
      GET_FULLBOX_VER_FLGS
      pcb = new MediaHeaderBox(sz, typ, ver, flgs);
    } else if (typ == MKTAG4('h', 'd', 'l', 'r')) {
      pcb = new HandlerBox(sz, typ);
    } else if (typ == MKTAG4('m', 'i', 'n', 'f')) {
      pcb = new MediaInformationBox(sz, typ);
    } else if (typ == MKTAG4('v', 'm', 'h', 'd')) {
      GET_FULLBOX_VER_FLGS
      pcb = new VideoMediaHeaderBox(sz, typ, ver, flgs);
    } else if (typ == MKTAG4('s', 'm', 'h', 'd')) {
      GET_FULLBOX_VER_FLGS
      pcb = new SoundMediaHeaderBox(sz, typ, ver, flgs);
    } else if (typ == MKTAG4('d', 'i', 'n', 'f')) {
      pcb = new DataInformationBox(sz, typ);
    } else if (typ == MKTAG4('d', 'r', 'e', 'f')) {
      GET_FULLBOX_VER_FLGS
      pcb = new DataReferenceBox(sz, typ, ver, flgs);
    } else if (typ == MKTAG4('u', 'r', 'l', ' ')) {
      GET_FULLBOX_VER_FLGS
      pcb = new DataEntryUrlBox(sz, typ, ver, flgs);
    } else if (typ == MKTAG4('s', 't', 'b', 'l')) {
      pcb = new SampleTableBox(sz, typ);
    } else if (typ == MKTAG4('s', 't', 's', 'd')) {
      GET_FULLBOX_VER_FLGS
      pcb = new SampleDescriptionBox(sz, typ, ver, flgs);
    } else if (typ == MKTAG4('a', 'v', 'c', '1')) {
      pcb = new VisualSampleEntry(sz, typ);
    } else if (typ == MKTAG4('a', 'v', 'c', 'C')) {
      pcb = new avcCBox(sz, typ);
    } else if (typ == MKTAG4('s', 't', 't', 's')) {
      GET_FULLBOX_VER_FLGS
      pcb = new TimeToSampleBox(sz, typ, ver, flgs);
    } else if (typ == MKTAG4('c', 't', 't', 's')) {
      GET_FULLBOX_VER_FLGS
      pcb = new CompositionOffsetBox(sz, typ, ver, flgs);
    } else if (typ == MKTAG4('s', 't', 's', 's')) {
      GET_FULLBOX_VER_FLGS
      pcb = new SyncSampleBox(sz, typ, ver, flgs);
    } else if (typ == MKTAG4('s', 't', 's', 'c')) {
      GET_FULLBOX_VER_FLGS
      pcb = new SampleToChunkBox(sz, typ, ver, flgs);
    } else if (typ == MKTAG4('s', 't', 's', 'z')) {
      GET_FULLBOX_VER_FLGS
      pcb = new SampleSizeBox(sz, typ, ver, flgs);
    } else if (typ == MKTAG4('s', 't', 'c', 'o')) {
      GET_FULLBOX_VER_FLGS
      pcb = new ChunkOffsetBox(sz, typ, ver, flgs);
    } else if (typ == MKTAG4('c', 'o', '6', '4')) {
      GET_FULLBOX_VER_FLGS
      pcb = new ChunkLargeOffsetBox(sz, typ, ver, flgs);
    } else if (typ == MKTAG4('m', 'p', '4', 'a')) {
      pcb = new mp4aBox(sz, typ);
    } else if (typ == MKTAG4('e', 's', 'd', 's')) {
      GET_FULLBOX_VER_FLGS
      pcb = new esdsBox(sz, typ, ver, flgs);
    } else if (typ == MKTAG4('e', 'd', 't', 's')) {
      pcb = new EditBox(sz, typ);
    } else if (typ == MKTAG4('e', 'l', 's', 't')) {
      GET_FULLBOX_VER_FLGS
      pcb = new EditListBox(sz, typ, ver, flgs);
    }

    if (pcb) {
      if (pcb->init(f) < 0) {
        SAFE_DELETE(pcb);
        goto skip;
      }

      if (!pb)
        pb = pcb;
      else
        pb->lnk_next(pcb);
    } else {
#ifdef XDEBUG
      LOGW("Unsupported box type: %s, size=%u (skipped)",
           typ_str(typ), sz);
#endif

skip:
      // Skip this box (NOT a largesize one)
      if (sz) {
        off_t skip_bytes = 0;
        if (sz == 1) {
          if (!largesz) {
            LOGE("Haven't got box's largesize, fatal");
            goto end_parse;
          }
          skip_bytes = largesz - (f->cursor() - cursave);
        } else {
          skip_bytes = sz - (f->cursor() - cursave);
        }
        f->seek_ahead(skip_bytes);
      } else {
end_parse:
        // This is the last box of file, seek to the end then break
        f->seek_end();
        break;
      }
    }
  }

  return 0;

#undef GET_FULLBOX_VER_FLGS
}

int Box::free_box(Box *&box)
{
  Box *p = box, *q;
  while (p) {
    q = p->next;
    free_box(p->sub);
    SAFE_DELETE(p);
    p = q;
  }
  return 0;
}

const char *Box::typ_str(uint32_t typ)
{
  static char tmp[5];
  tmp[0] = (typ&0xFF000000)>>24;
  tmp[1] = (typ&0x00FF0000)>>16;
  tmp[2] = (typ&0x0000FF00)>>8;
  tmp[3] = (typ&0x000000FF);
  tmp[4] = '\0';
  return tmp;
}

/////////////////////////////////////////////////////////////

FullBox::FullBox(uint32_t _sz, uint32_t _typ,
                 uint8_t _ver, const uint24_t &_flgs) :
  Box(_sz, _typ),
  ver(_ver)
{
  memcpy(flgs, _flgs, sizeof(uint24_t));
}

int FullBox::init(File *f)
{
  LOGW("Shouldn't call FullBox's init() function");
  return 0;
}

void FullBox::print() const
{
  Box::print();

#ifdef XDEBUG
  printf("version: %u\n", ver);
  printf("flags: 0x%02x 0x%02x 0x%02x\n",
         flgs[0], flgs[1], flgs[2]);
#endif
}

/////////////////////////////////////////////////////////////

FileTypeBox::FileTypeBox(uint32_t _sz, uint32_t _typ) :
  Box(_sz, _typ)
{
}

int FileTypeBox::init(File *f)
{
  // Boxes except "mdat" always use sz not largesz
  uint8_t *tmp = new uint8_t[sz-8], *p = tmp;
  if (!f->read_buffer(tmp, sz-8)) {
    LOGE("Read box \"ftyp\" content failed");
    SAFE_DELETE_ARRAY(tmp);
    return -1;
  }

  major_brand = ENTOHL(*((uint32_t *) p));
  p += 4;
  minor_brand = ENTOHL(*((uint32_t *) p));
  p += 4;

  while (p < tmp + sz - 8) {
    compatible_brands.push_back(ENTOHL(*((uint32_t *) p)));
    p += 4;
  }

#ifdef XDEBUG
  printf("major_brand: 0x%08x, minor_brand: 0x%08x\n",
         major_brand, minor_brand);
  printf("compatible_brands: ");
  FOR_VECTOR_ITERATOR(uint32_t, compatible_brands, it) {
    printf("0x%08x ", *it);
  }
  printf("\n");
#endif

  SAFE_DELETE_ARRAY(tmp);
  return 0;
}

/////////////////////////////////////////////////////////////

MediaDataBox::MediaDataBox(uint32_t _sz, uint32_t _typ, uint64_t _largesz) :
  Box(_sz, _typ, _largesz)
{
}

int MediaDataBox::init(File *f)
{
  // Figure out whether "mdat" is a largesize box, and then skip it
  return f->seek_ahead(getsz() - (sz != 1 ? 8 : 16)) ? 0 : -1;
}

/////////////////////////////////////////////////////////////

MovieBox::MovieBox(uint32_t _sz, uint32_t _typ) :
  Box(_sz, _typ)
{
}

int MovieBox::init(File *f)
{
  return parse_box(sub, f, f->cursor() + sz - 8);
}

/////////////////////////////////////////////////////////////

MovieHeaderBox::MovieHeaderBox(uint32_t _sz, uint32_t _typ,
                               uint8_t _ver, const uint24_t &_flgs) :
  FullBox(_sz, _typ, _ver, _flgs)
{
}

int MovieHeaderBox::init(File *f)
{
  FullBox::print();

  /* REFERENCE
   * if (version==1) {
   *     unsigned int(64) creation_time;
   *     unsigned int(64) modification_time;
   *     unsigned int(32) timescale;
   *     unsigned int(64) duration;
   * } else { // version==0
   *     unsigned int(32) creation_time;
   *     unsigned int(32) modification_time;
   *     unsigned int(32) timescale; 
   *     unsigned int(32) duration;
   * } 
   * template int(32)  rate = 0x00010000; // typically 1.0 
   * template int(16)  volume = 0x0100;   // typically, full volume 
   * const bit(16)  reserved = 0; 
   * const unsigned int(32)[2]  reserved = 0; 
   * template int(32)[9] matrix = 
   * { 0x00010000,0,0,0,0x00010000,0,0,0,0x40000000 }; 
   * // Unity matrix 
   * bit(32)[6]  pre_defined = 0; 
   * unsigned int(32) next_track_ID;
   */

  if (ver == 1) {
    if (!f->readui64(&creation_time.u64, true)) {
      LOGE("Read \"mvhd\" creation_time(64) failed");
      return -1;
    }

    if (!f->readui64(&modification_time.u64, true)) {
      LOGE("Read \"mvhd\" modification_time(64) failed");
      return -1;
    }

    if (!f->readui32(&timescale, true)) {
      LOGE("Read \"mvhd\" timescale failed");
      return -1;
    }

    if (!f->readui64(&duration.u64, true)) {
      LOGE("Read \"mvhd\" duration(64) failed");
      return -1;
    }
  } else { // ver == 0
    if (!f->readui32(&creation_time.u32, true)) {
      LOGE("Read \"mvhd\" creation_time failed");
      return -1;
    }

    if (!f->readui32(&modification_time.u32, true)) {
      LOGE("Read \"mvhd\" modification_time failed");
      return -1;
    }

    if (!f->readui32(&timescale, true)) {
      LOGE("Read \"mvhd\" timescale failed");
      return -1;
    }

    if (!f->readui32(&duration.u32, true)) {
      LOGE("Read \"mvhd\" duration failed");
      return -1;
    }
  }

  if (!f->readi32(&rate, true)) {
    LOGE("Read \"mvhd\" rate failed");
    return -1;
  }

  if (!f->readi16(&volume, true)) {
    LOGE("Read \"mvhd\" volume failed");
    return -1;
  }

  if (!f->readui16(&reserved16, true)) {
    LOGE("Read \"mvhd\" reserved16 failed");
    return -1;
  }

  for (int i = 0; i < 2; ++i) {
    if (!f->readui32(&reserved32[i], true)) {
      LOGE("Read \"mvhd\" reserved32[%d] failed", i);
      return -1;
    }
  }

  for (int i = 0; i < 9; ++i) {
    if (!f->readi32(&matrix[i], true)) {
      LOGE("Read \"mvhd\" matrix[%d] failed", i);
      return -1;
    }
  }

  for (int i = 0; i < 6; ++i) {
    if (!f->readui32(&pre_defined[i], true)) {
      LOGE("Read \"mvhd\" pre_defined[%d] failed", i);
      return -1;
    }
  }

  if (!f->readui32(&next_track_ID, true)) {
    LOGE("Read \"mvhd\" next_track_ID failed");
    return -1;
  }

#ifdef XDEBUG
  if (ver == 1) {
    printf("creation_time: %llu\n", (unsigned long long) creation_time.u64);
    printf("modification_time: %llu\n", (unsigned long long) modification_time.u64);
    printf("timescale: %u\n", timescale);
    printf("duration: %llu\n", (unsigned long long) duration.u64);
  } else {
    printf("creation_time: %u\n", creation_time.u32);
    printf("modification_time: %u\n", modification_time.u32);
    printf("timescale: %u\n", timescale);
    printf("duration: %u\n", duration.u32);
  }
  printf("rate: %d.%d\n", (rate&0xFF)>>16, rate&0xFF);
  printf("volume: %d.%d\n", (volume&0xF)>>8, volume&0xF);
  printf("reserved16: %d\n", reserved16);
  printf("reserved32: { ");
  for (int i = 0; i < 2; ++i) {
    printf("%u ", reserved32[i]);
  }
  printf("}\n");
  printf("matrix: { ");
  for (int i = 0; i < 9; ++i) {
    printf("%d ", matrix[i]);
  }
  printf("pre_defined: { ");
  for (int i = 0; i < 6; ++i) {
    printf("%u ", pre_defined[i]);
  }
  printf("}\n");
  printf("next_track_ID: %u\n", next_track_ID);
#endif
  return 0;
}

/////////////////////////////////////////////////////////////

TrackBox::TrackBox(uint32_t _sz, uint32_t _typ) :
  Box(_sz, _typ)
{
}

int TrackBox::init(File *f)
{
  return parse_box(sub, f, f->cursor() + sz - 8);
}

/////////////////////////////////////////////////////////////

TrackHeaderBox::TrackHeaderBox(uint32_t _sz, uint32_t _typ,
                               uint8_t _ver, const uint24_t &_flgs) :
  FullBox(_sz, _typ, _ver, _flgs)
{
}

int TrackHeaderBox::init(File *f)
{
  FullBox::print();

  /* REFERENCE
   * if (version==1) { 
   *     unsigned int(64) creation_time; 
   *     unsigned int(64) modification_time; 
   *     unsigned int(32) track_ID; 
   *     const unsigned int(32)  reserved = 0; 
   *     unsigned int(64) duration; 
   * } else { // version==0 
   *     unsigned int(32) creation_time; 
   *     unsigned int(32) modification_time; 
   *     unsigned int(32) track_ID; 
   *     const unsigned int(32)  reserved = 0; 
   *     unsigned int(32) duration; 
   * } 
   * const unsigned int(32)[2]  reserved = 0; 
   * template int(16) layer = 0; 
   * template int(16) alternate_group = 0; 
   * template int(16) volume = {if track_is_audio 0x0100 else 0}; 
   * const unsigned int(16)  reserved = 0; 
   * template int(32)[9] matrix= 
   * { 0x00010000,0,0,0,0x00010000,0,0,0,0x40000000 }; 
   * // unity matrix 
   * unsigned int(32) width; 
   * unsigned int(32) height;
   */

  if (ver == 1) {
    if (!f->readui64(&creation_time.u64, true)) {
      LOGE("Read \"tkhd\" creation_time(64) failed");
      return -1;
    }

    if (!f->readui64(&modification_time.u64, true)) {
      LOGE("Read \"tkhd\" modification_time(64) failed");
      return -1;
    }

    if (!f->readui32(&track_ID, true)) {
      LOGE("Read \"tkhd\" track_ID failed");
      return -1;
    }

    if (!f->readui32(&reserved0, true)) {
      LOGE("Read \"tkhd\" reserved0 failed");
      return -1;
    }

    if (!f->readui64(&duration.u64, true)) {
      LOGE("Read \"tkhd\" duration(64) failed");
      return -1;
    }
  } else { // ver == 0
    if (!f->readui32(&creation_time.u32, true)) {
      LOGE("Read \"tkhd\" creation_time failed");
      return -1;
    }

    if (!f->readui32(&modification_time.u32, true)) {
      LOGE("Read \"tkhd\" modification_time failed");
      return -1;
    }

    if (!f->readui32(&track_ID, true)) {
      LOGE("Read \"tkhd\" track_ID failed");
      return -1;
    }

    if (!f->readui32(&reserved0, true)) {
      LOGE("Read \"tkhd\" reserved0 failed");
      return -1;
    }

    if (!f->readui32(&duration.u32, true)) {
      LOGE("Read \"tkhd\" duration failed");
      return -1;
    }
  }

  for (int i = 0; i < 2; ++i) {
    if (!f->readui32(&reserved1[i], true)) {
      LOGE("Read \"tkhd\" reserved1[%d] failed", i);
      return -1;
    }
  }

  if (!f->readi16(&layer, true)) {
    LOGE("Read \"tkhd\" layer failed");
    return -1;
  }

  if (!f->readi16(&alternate_group, true)) {
    LOGE("Read \"tkhd\" alternate_group failed");
    return -1;
  }

  if (!f->readi16(&volume, true)) {
    LOGE("Read \"tkhd\" volume failed");
    return -1;
  }

  if (!f->readui16(&reserved2, true)) {
    LOGE("Read \"tkhd\" reserved2 failed");
    return -1;
  }

  for (int i = 0; i < 9; ++i) {
    if (!f->readi32(&matrix[i], true)) {
      LOGE("Read \"tkhd\" matrix[%d] failed", i);
      return -1;
    }
  }

  if (!f->readui32(&width, true)) {
    LOGE("Read \"tkhd\" width failed");
    return -1;
  }
  // Convert fixed-point 16.16 value to uint32_t
  width = float(width)/65536.0f;

  if (!f->readui32(&height, true)) {
    LOGE("Read \"tkhd\" height failed");
    return -1;
  }
  height = float(height)/65536.0f;

#ifdef XDEBUG
  if (ver == 1) {
    printf("creation_time: %llu\n", (unsigned long long) creation_time.u64);
    printf("modification_time: %llu\n", (unsigned long long) modification_time.u64);
    printf("track_ID: %u\n", track_ID);
    printf("reserved0: %u\n", reserved0);
    printf("duration: %llu\n", (unsigned long long) duration.u64);
  } else {
    printf("creation_time: %u\n", creation_time.u32);
    printf("modification_time: %u\n", modification_time.u32);
    printf("track_ID: %u\n", track_ID);
    printf("reserved0: %u\n", reserved0);
    printf("duration: %u\n", duration.u32);
  }
  printf("reserved1: { ");
  for (int i = 0; i < 2; ++i) {
    printf("%u ", reserved1[i]);
  }
  printf("}\n");
  printf("layer: %d\n", layer);
  printf("alternate_group: %d\n", alternate_group);
  printf("volume: %d\n", volume);
  printf("reserved2: %u\n", reserved2);
  printf("matrix: { ");
  for (int i = 0; i < 9; ++i) {
    printf("%d ", matrix[i]);
  }
  printf("}\n");
  printf("width: %u\n", width);
  printf("height: %u\n", height);
#endif
  return 0;
}

/////////////////////////////////////////////////////////////

MediaBox::MediaBox(uint32_t _sz, uint32_t _typ) :
  Box(_sz, _typ)
{
}

int MediaBox::init(File *f)
{
  return parse_box(sub, f, f->cursor() + sz - 8);
}

/////////////////////////////////////////////////////////////

MediaHeaderBox::MediaHeaderBox(uint32_t _sz, uint32_t _typ,
                               uint8_t _ver, const uint24_t &_flgs) :
  FullBox(_sz, _typ, _ver, _flgs)
{
}

int MediaHeaderBox::init(File *f)
{
  FullBox::print();

  /* REFERENCE
   * if (version==1) { 
   *     unsigned int(64) creation_time; 
   *     unsigned int(64) modification_time; 
   *     unsigned int(32) timescale; 
   *     unsigned int(64) duration; 
   * } else { // version==0 
   *     unsigned int(32) creation_time; 
   *     unsigned int(32) modification_time; 
   *     unsigned int(32) timescale; 
   *     unsigned int(32) duration; 
   * } 
   * bit(1) pad = 0; 
   * unsigned int(5)[3]  language;  // ISO-639-2/T language code 
   * unsigned int(16)  pre_defined = 0;
   */
  if (ver == 1) {
    if (!f->readui64(&creation_time.u64, true)) {
      LOGE("Read \"mdhd\" creation_time(64) failed");
      return -1;
    }

    if (!f->readui64(&modification_time.u64, true)) {
      LOGE("Read \"mdhd\" modification_time(64) failed");
      return -1;
    }

    if (!f->readui32(&timescale, true)) {
      LOGE("Read \"mdhd\" timescale failed");
      return -1;
    }

    if (!f->readui64(&duration.u64, true)) {
      LOGE("Read \"mdhd\" duration(64) failed");
      return -1;
    }
  } else { // ver == 0
    if (!f->readui32(&creation_time.u32, true)) {
      LOGE("Read \"mdhd\" creation_time failed");
      return -1;
    }

    if (!f->readui32(&modification_time.u32, true)) {
      LOGE("Read \"mdhd\" modification_time failed");
      return -1;
    }

    if (!f->readui32(&timescale, true)) {
      LOGE("Read \"mdhd\" timescale failed");
      return -1;
    }

    if (!f->readui32(&duration.u32, true)) {
      LOGE("Read \"mdhd\" duration failed");
      return -1;
    }
  }

  uint16_t u16;
  if (!f->readui16(&u16, true)) {
    LOGE("Read \"mdhd\" pad&language failed");
    return -1;
  }
  pad = !!(u16&0x8000);
  language[0] = (u16&0x7C00)>>10;
  language[1] = (u16&0x3E0)>>5;
  language[2] = (u16&0x1F);

  if (!f->readui16(&pre_defined, true)) {
    LOGE("Read \"mdhd\" pre_defined failed");
    return -1;
  }

#ifdef XDEBUG
  if (ver == 1) {
    printf("creation_time: %llu\n", (unsigned long long) creation_time.u64);
    printf("modification_time: %llu\n", (unsigned long long) modification_time.u64);
    printf("timescale: %u\n", timescale);
    printf("duration: %llu\n", (unsigned long long) duration.u64);
  } else {
    printf("creation_time: %u\n", creation_time.u32);
    printf("modification_time: %u\n", modification_time.u32);
    printf("timescale: %u\n", timescale);
    printf("duration: %u\n", duration.u32);
  }
  printf("pad: %u\n", pad);
  printf("language: %u %u %u\n",
         language[0], language[1], language[2]);
  printf("pre_defined: %u\n", pre_defined);
#endif
  return 0;
}

/////////////////////////////////////////////////////////////

HandlerBox::HandlerBox(uint32_t _sz, uint32_t _typ) :
  Box(_sz, _typ)
{
}

int HandlerBox::init(File *f)
{
  off_t cursave = f->cursor();

  /* REFERENCE
   * unsigned int(32) pre_defined = 0;
   * unsigned int(32) handler_type;
   * const unsigned int(32)[3] reserved = 0;
   * string name;
   */
  if (!f->readui32(&pre_defined, true)) {
    LOGE("Read \"hdlr\" pre_defined failed");
    return -1;
  }

  if (!f->readui32(&handler_type, true)) {
    LOGE("Read \"hdlr\" handler_type failed");
    return -1;
  }

  for (int i = 0; i < 3; ++i) {
    if (!f->readui32(&reserved[i], true)) {
      LOGE("Read \"hdlr\" reserved[%d] failed", i);
      return -1;
    }
  }

  uint32_t max_name_len = sz - (f->cursor() - cursave) - 8;
  uint8_t *tmp = new uint8_t[max_name_len];
  if (!f->read_buffer(tmp, max_name_len)) {
    LOGE("Read \"hdlr\" name failed");
    SAFE_DELETE_ARRAY(tmp);
    return -1;
  }
  name = std::string((char *) tmp);
  SAFE_DELETE_ARRAY(tmp);

#ifdef XDEBUG
  printf("pre_defined: %u\n", pre_defined);
  printf("handler_type: 0x%08x\n", handler_type);
  printf("reserved: { ");
  for (int i = 0; i < 3; ++i) {
    printf("%u ", reserved[i]);
  }
  printf("}\n");
  printf("name: %s\n", STR(name));
#endif
  return 0;
}

/////////////////////////////////////////////////////////////

MediaInformationBox::MediaInformationBox(uint32_t _sz, uint32_t _typ) :
  Box(_sz, _typ)
{
}

int MediaInformationBox::init(File *f)
{
  return parse_box(sub, f, f->cursor() + sz - 8);
}

/////////////////////////////////////////////////////////////

VideoMediaHeaderBox::VideoMediaHeaderBox(uint32_t _sz, uint32_t _typ,
                                         uint8_t _ver, const uint24_t &_flgs) :
  FullBox(_sz, _typ, _ver, _flgs)
{
}

int VideoMediaHeaderBox::init(File *f)
{
  FullBox::print();

  /* REFERENCE
   * template unsigned int(16) graphicsmode = 0; // copy, see below
   * template unsigned int(16)[3] opcolor = {0, 0, 0};
   */
  if (!f->readui16(&graphicsmode, true)) {
    LOGE("Read \"vmhd\" graphicsmode failed");
    return -1;
  }

  for (int i = 0; i < 3; ++i) {
    if (!f->readui16(&opcolor[i], true)) {
      LOGE("Read \"vmhd\" opcolor[%d] failed", i);
      return -1;
    }
  }

#ifdef XDEBUG
  printf("graphicsmode: %u\n", graphicsmode);
  printf("opcolor: { ");
  for (int i = 0; i < 3; ++i) {
    printf("%u ", opcolor[i]);
  }
  printf("}\n");
#endif
  return 0;
}

/////////////////////////////////////////////////////////////

SoundMediaHeaderBox::SoundMediaHeaderBox(uint32_t _sz, uint32_t _typ,
                                         uint8_t _ver, const uint24_t &_flgs) :
  FullBox(_sz, _typ, _ver, _flgs)
{
}

int SoundMediaHeaderBox::init(File *f)
{
  FullBox::print();

  /* REFERENCE
   * template int(16) balance = 0;
   * const unsigned int(16) reserved = 0;
   */
  if (!f->readi16(&balance, true)) {
    LOGE("Read \"smhd\" balance failed");
    return -1;
  }

  if (!f->readui16(&reserved, true)) {
    LOGE("Read \"smhd\" reserved failed");
    return -1;
  }

#ifdef XDEBUG
  printf("balance: %d\n", balance);
  printf("reserved: %u\n", reserved);
#endif
  return 0;
}

/////////////////////////////////////////////////////////////


DataInformationBox::DataInformationBox(uint32_t _sz, uint32_t _typ) :
  Box(_sz, _typ)
{
}

int DataInformationBox::init(File *f)
{
  return parse_box(sub, f, f->cursor() + sz - 8);
}

/////////////////////////////////////////////////////////////

DataReferenceBox::DataReferenceBox(uint32_t _sz, uint32_t _typ,
                                   uint8_t _ver, const uint24_t &_flgs) :
  FullBox(_sz, _typ, _ver, _flgs)
{
}

int DataReferenceBox::init(File *f)
{
  FullBox::print();

  /* REFERENCE
   * unsigned int(32) entry_count;
   * for (i=1; i <= entry_count; i++) {
   * DataEntryBox(entry_version, entry_flags) data_entry;
   */
  if (!f->readui32(&entry_count, true)) {
    LOGE("Read \"dref\" entry_count failed");
    return -1;
  }

#ifdef XDEBUG
  printf("entry_count: %u\n", entry_count);
#endif
  return 0;
}

/////////////////////////////////////////////////////////////

DataEntryUrlBox::DataEntryUrlBox(uint32_t _sz, uint32_t _typ,
                                 uint8_t _ver, const uint24_t &_flgs) :
  FullBox(_sz, _typ, _ver, _flgs)
{
}

int DataEntryUrlBox::init(File *f)
{
  FullBox::print();

  /* REFERENCE
   * string location
   */
  uint32_t max_location_len = sz - 12 /*sz+typ+ver+flgs=12bytes*/;
  if (!max_location_len) {
    location = "same file";
  } else {
    uint8_t *tmp = new uint8_t[max_location_len];
    if (!f->read_buffer(tmp, max_location_len)) {
      LOGE("Read \"url\" location failed");
      SAFE_DELETE_ARRAY(tmp);
      return -1;
    }
    location = std::string((char *) tmp);
    SAFE_DELETE_ARRAY(tmp);
  }

#ifdef XDEBUG
  printf("location: %s\n", STR(location));
#endif
  return 0;
}

/////////////////////////////////////////////////////////////

SampleTableBox::SampleTableBox(uint32_t _sz, uint32_t _typ) :
  Box(_sz, _typ)
{
}

int SampleTableBox::init(File *f)
{
  return parse_box(sub, f, f->cursor() + sz - 8);
}

/////////////////////////////////////////////////////////////

SampleDescriptionBox::SampleDescriptionBox(uint32_t _sz, uint32_t _typ,
                                           uint8_t _ver, const uint24_t &_flgs) :
  FullBox(_sz, _typ, _ver, _flgs)
{
}

SampleDescriptionBox::~SampleDescriptionBox()
{
  for (uint32_t i = 0; i < entry_count; ++i) {
    Box *box = (Box *) elem[i];
    free_box(box);
  }
  SAFE_DELETE_ARRAY(elem);
}

int SampleDescriptionBox::init(File *f)
{
  FullBox::print();

  /* REFERENCE
   * unsigned int(32) entry_count;
   * for (int i = 1 ; i <= entry_count ; i++){
   *     switch (handler_type){
   *         case ‘soun’: // for audio tracks
   *             AudioSampleEntry();
   *             break;
   *         case ‘vide’: // for video tracks
   *             VisualSampleEntry();
   *             break;
   *         case ‘hint’: // Hint track
   *             HintSampleEntry();
   *             break;
   *         case ‘meta’: // Metadata track
   *             MetadataSampleEntry();
   *             break;
   *     }
   * }
   */
  if (!f->readui32(&entry_count, true)) {
    LOGE("Read \"stsd\" entry_count failed");
    return -1;
  }

#ifdef XDEBUG
  printf("entry_count: %u\n", entry_count);
#endif

  if (!entry_count)
    return 0;

  elem = new SampleEntry *[entry_count];
  for (uint32_t i = 0; i < entry_count; ++i) {
    Box *box = NULL;
    if (parse_box(box, f, -1) < 0) {
      LOGE("Parse \"stsd\" entry failed");
      SAFE_DELETE_ARRAY(elem);
      return -1;
    }
    elem[i] = (SampleEntry *) box;
  }
  return 0;
}

/////////////////////////////////////////////////////////////

SampleEntry::SampleEntry(uint32_t _sz, uint32_t _typ) :
  Box(_sz, _typ)
{
}

int SampleEntry::init(File *f)
{
  /* REFERENCE
   * const unsigned int(8)[6] reserved = 0;
   * unsigned int(16) data_reference_index;
   */
  for (int i = 0; i < 6; ++i) {
    if (!f->readui8(&reserved[i])) {
      LOGE("Read \"%s\" reserved[%d] failed",
           typ_str(typ), i);
      return -1;
    }
  }

  if (!f->readui16(&data_reference_index)) {
    LOGE("Read \"%s\" data_reference_index failed",
         typ_str(typ));
    return -1;
  }

#ifdef XDEBUG
  printf("reserved: { ");
  for (int i = 0; i < 6; ++i) {
    printf("%u ", reserved[i]);
  }
  printf("}\n");
  printf("data_reference_index: %u\n", data_reference_index);
#endif
  return 0;
}

/////////////////////////////////////////////////////////////

VisualSampleEntry::VisualSampleEntry(uint32_t _sz, uint32_t _typ) :
  SampleEntry(_sz, _typ)
{
}

int VisualSampleEntry::init(File *f)
{
  off_t cursave = f->cursor();

  if (SampleEntry::init(f) < 0)
    return -1;

  /* REFERENCE
   * unsigned int(16) pre_defined = 0;
   * const unsigned int(16) reserved = 0;
   * unsigned int(32)[3] pre_defined = 0;
   * unsigned int(16) width;
   * unsigned int(16) height;
   * template unsigned int(32) horizresolution = 0x00480000; // 72 dpi
   * template unsigned int(32) vertresolution = 0x00480000; // 72 dpi
   * const unsigned int(32) reserved = 0;
   * template unsigned int(16) frame_count = 1;
   * string[32] compressorname;
   * template unsigned int(16) depth = 0x0018;
   * int(16) pre_defined = -1;
   * // other boxes from derived specifications
   * CleanApertureBox clap; // optional
   * PixelAspectRatioBox pasp; // optional
   */
  if (!f->readui16(&pre_defined, true)) {
    LOGE("Read \"%s\" pre_defined failed",
         typ_str(typ));
    return -1;
  }

  if (!f->readui16(&reserved1, true)) {
    LOGE("Read \"%s\" reserved1 failed",
         typ_str(typ));
    return -1;
  }

  for (int i = 0; i < 3; ++i) {
    if (!f->readui32(&pre_defined1[i], true)) {
      LOGE("Read \"%s\" pre_defined1[%d] failed",
           typ_str(typ), i);
      return -1;
    }
  }

  if (!f->readui16(&width, true)) {
    LOGE("Read \"%s\" width failed",
         typ_str(typ));
    return -1;
  }

  if (!f->readui16(&height, true)) {
    LOGE("Read \"%s\" height failed",
         typ_str(typ));
    return -1;
  }

  if (!f->readui32(&horizresolution, true)) {
    LOGE("Read \"%s\" horizresolution failed",
         typ_str(typ));
    return -1;
  }

  if (!f->readui32(&vertresolution, true)) {
    LOGE("Read \"%s\" vertresolution failed",
         typ_str(typ));
    return -1;
  }

  if (!f->readui32(&reserved2, true)) {
    LOGE("Read \"%s\" reserved2 failed",
         typ_str(typ));
    return -1;
  }

  if (!f->readui16(&frame_count, true)) {
    LOGE("Read \"%s\" frame_count failed",
         typ_str(typ));
    return -1;
  }

  if (!f->read_buffer((uint8_t *) compressorname, 32)) {
    LOGE("Read \"%s\" compressorname failed",
         typ_str(typ));
    return -1;
  }

  if (!f->readui16(&depth, true)) {
    LOGE("Read \"%s\" depth failed",
         typ_str(typ));
    return -1;
  }

  if (!f->readi16(&pre_defined2, true)) {
    LOGE("Read \"%s\" pre_defined2 failed",
         typ_str(typ));
    return -1;
  }

#ifdef XDEBUG
  printf("pre_defined: %u\n", pre_defined);
  printf("reserved1: %u\n", reserved1);
  printf("pre_defined1: { ");
  for (int i = 0; i < 3; ++i) {
    printf("%u ", pre_defined1[i]);
  }
  printf("}\n");
  printf("width: %u\n", width);
  printf("height: %u\n", height);
  printf("horizresolution: %u\n", horizresolution);
  printf("vertresolution: %u\n", vertresolution);
  printf("reserved2: %u\n", reserved2);
  printf("frame_count: %u\n", frame_count);
  printf("compressorname: %.*s\n",
         compressorname[0], compressorname+1);
  printf("depth: %u\n", depth);
  printf("pre_defined2: %d\n", pre_defined2);
#endif

  return parse_box(sub, f, (f->cursor() - cursave) + sz - 8);
}

/////////////////////////////////////////////////////////////

avcCBox::avcCBox(uint32_t _sz, uint32_t _typ) :
  Box(_sz, _typ)
{
}

avcCBox::~avcCBox()
{
  SAFE_DELETE_ARRAY(avc_dcr.sps);
  SAFE_DELETE_ARRAY(avc_dcr.pps);
}

int avcCBox::init(File *f)
{
  uint8_t *tmp = new uint8_t[sz - 8], *p = tmp;
  if (!f->read_buffer(tmp, sz - 8)) {
    LOGE("Read \"avcC\" buffer failed");
    SAFE_DELETE_ARRAY(tmp);
    return -1;
  }

  avc_dcr.version = *p++;
  avc_dcr.profile = *p++;
  avc_dcr.profile_compatibility = *p++;
  avc_dcr.level = *p++;
  *(uint8_t*)(&avc_dcr.level + 1) = *p++;
  *(uint8_t*)(&avc_dcr.level + 2) = *p++;
  avc_dcr.sps_length = ENTOHS(*(uint16_t *)p);
  p += sizeof(uint16_t);
  avc_dcr.sps = new byte[avc_dcr.sps_length];
  memcpy(avc_dcr.sps, p, avc_dcr.sps_length);
  p += avc_dcr.sps_length;
  avc_dcr.num_of_pps = *p++;
  avc_dcr.pps_length = ENTOHS(*(uint16_t *)p);
  p += sizeof(uint16_t);
  avc_dcr.pps = new byte[avc_dcr.pps_length];
  memcpy(avc_dcr.pps, p, avc_dcr.pps_length);
  p += avc_dcr.pps_length;

  SAFE_DELETE_ARRAY(tmp);

#ifdef XDEBUG
  print_avc_dcr(avc_dcr);
#endif
  return 0;
}

/////////////////////////////////////////////////////////////

TimeToSampleBox::TimeToSampleBox(uint32_t _sz, uint32_t _typ,
                                 uint8_t _ver, const uint24_t &_flgs) :
  FullBox(_sz, _typ, _ver, _flgs)
{
  sample_count = NULL;
  sample_delta = NULL;
}

TimeToSampleBox::~TimeToSampleBox()
{
  SAFE_DELETE_ARRAY(sample_count);
  SAFE_DELETE_ARRAY(sample_delta);
}

int TimeToSampleBox::init(File *f)
{
  FullBox::print();

  /* REFERENCE
   * unsigned int(32) entry_count;
   * for (int i=0; i < entry_count; i++) {
   *     unsigned int(32) sample_count;
   *     unsigned int(32) sample_delta;
   * }
   */
  if (!f->readui32(&entry_count, true)) {
    LOGE("Read \"stts\" entry_count failed");
    return -1;
  }

  uint32_t tmp_len = sz - 12 - 4/*entry_count's size*/;
  uint8_t *tmp = new uint8_t[tmp_len];
  if (!f->read_buffer(tmp, tmp_len)) {
    LOGE("Read \"stts\" content failed");
    SAFE_DELETE_ARRAY(tmp);
    return -1;
  }

  uint32_t *p = (uint32_t *) tmp;
  sample_count = new uint32_t[entry_count];
  sample_delta = new uint32_t[entry_count];
  for (uint32_t i = 0; i < entry_count; ++i) {
    sample_count[i] = ENTOHL(*p);
    ++p;
    sample_delta[i] = ENTOHL(*p);
    ++p;
  }

#ifdef XDEBUG
  printf("entry_count: %u\n", entry_count);
#if XDEBUG_FULL
  for (uint32_t i = 0; i < entry_count; ++i) {
    printf("sample_count: %u\n", sample_count[i]);
    printf("sample_delta: %u\n", sample_delta[i]);
  }
#endif
#endif

  SAFE_DELETE_ARRAY(tmp);
  return 0;
}

/////////////////////////////////////////////////////////////


CompositionOffsetBox::CompositionOffsetBox(uint32_t _sz, uint32_t _typ,
                                           uint8_t _ver, const uint24_t &_flgs) :
  FullBox(_sz, _typ, _ver, _flgs),
  entry_count(0), sample_count(NULL), sample_offset(NULL)
{
}

CompositionOffsetBox::~CompositionOffsetBox()
{
  SAFE_DELETE_ARRAY(sample_count);
  SAFE_DELETE_ARRAY(sample_offset);
}

int CompositionOffsetBox::init(File *f)
{
  FullBox::print();

  /* REFERENCE
   * unsigned int(32) entry_count;
   * int i;
   * if (version==0) {
   *   for (i=0; i < entry_count; i++) {
   *     unsigned int(32)  sample_count;
   *     unsigned int(32)  sample_offset;
   *   }
   * }
   * else if (version == 1) {
   *   for (i=0; i < entry_count; i++) {
   *     unsigned int(32)  sample_count;
   *     signed   int(32)  sample_offset;
   *   }
   * }
   */
  if (!f->readui32(&entry_count, true)) {
    LOGE("Read \"ctts\" entry_count failed");
    return -1;
  }

  uint32_t tmp_len = sz - 12 - 4/*entry_count's size*/;
  uint8_t *tmp = new uint8_t[tmp_len];
  if (!f->read_buffer(tmp, tmp_len)) {
    LOGE("Read \"ctts\" content failed");
    SAFE_DELETE_ARRAY(tmp);
    return -1;
  }

  uint32_t *p = (uint32_t *) tmp;
  sample_count = new uint32_t[entry_count];
  sample_offset = new uint32_t[entry_count];
  for (uint32_t i = 0; i < entry_count; ++i) {
    sample_count[i] = ENTOHL(*p);
    ++p;
    sample_offset[i] = ENTOHL(*p);
    ++p;
  }

#ifdef XDEBUG
  printf("entry_count: %u\n", entry_count);
#if XDEBUG_FULL
  for (uint32_t i = 0; i < entry_count; ++i) {
    printf("sample_count: %u\n", sample_count[i]);
    printf("sample_offset: %u\n", sample_offset[i]);
  }
#endif
#endif

  SAFE_DELETE_ARRAY(tmp);
  return 0;
}

/////////////////////////////////////////////////////////////

SyncSampleBox::SyncSampleBox(uint32_t _sz, uint32_t _typ,
                             uint8_t _ver, const uint24_t &_flgs) :
  FullBox(_sz, _typ, _ver, _flgs)
{
  sample_number = NULL;
}

SyncSampleBox::~SyncSampleBox()
{
  SAFE_DELETE_ARRAY(sample_number);
}

int SyncSampleBox::init(File *f)
{
  FullBox::print();

  /* REFERENCE
   * unsigned int(32) entry_count;
   * for (int i=0; i < entry_count; i++) {
   *     unsigned int(32) sample_number;
   * }
   */
  if (!f->readui32(&entry_count, true)) {
    LOGE("Read \"stss\" entry_count failed");
    return -1;
  }

  uint32_t tmp_len = sz - 12 - 4/*entry_count's size*/;
  uint8_t *tmp = new uint8_t[tmp_len];
  if (!f->read_buffer(tmp, tmp_len)) {
    LOGE("Read \"stss\" content failed");
    SAFE_DELETE_ARRAY(tmp);
    return -1;
  }

  uint32_t *p = (uint32_t *) tmp;
  sample_number = new uint32_t[entry_count];
  for (uint32_t i = 0; i < entry_count; ++i) {
    sample_number[i] = ENTOHL(*p);
    ++p;
  }

#ifdef XDEBUG
  printf("entry_count: %u\n", entry_count);
#if XDEBUG_FULL
  for (uint32_t i = 0; i < entry_count; ++i) {
    printf("sample_number: 0x%08x\n", sample_number[i]);
  }
#endif
#endif

  SAFE_DELETE_ARRAY(tmp);
  return 0;
}

/////////////////////////////////////////////////////////////

SampleToChunkBox::SampleToChunkBox(uint32_t _sz, uint32_t _typ,
                                   uint8_t _ver, const uint24_t &_flgs) :
  FullBox(_sz, _typ, _ver, _flgs)
{
  first_chunk = NULL;
  sample_per_chunk = NULL;
  sample_description_index = NULL;
}

SampleToChunkBox::~SampleToChunkBox()
{
  SAFE_DELETE_ARRAY(first_chunk);
  SAFE_DELETE_ARRAY(sample_per_chunk);
  SAFE_DELETE_ARRAY(sample_description_index);
}

int SampleToChunkBox::init(File *f)
{
  FullBox::print();

  /* REFERENCE
   * unsigned int(32) entry_count;
   * for (i=1; i <= entry_count; i++) {
   *     unsigned int(32) first_chunk;
   *     unsigned int(32) samples_per_chunk;
   *     unsigned int(32) sample_description_index;
   * }
   */
  if (!f->readui32(&entry_count, true)) {
    LOGE("Read \"stsc\" entry_count failed");
    return -1;
  }

  uint32_t tmp_len = sz - 12 - 4;
  uint8_t *tmp = new uint8_t[tmp_len];
  if (!f->read_buffer(tmp, tmp_len)) {
    LOGE("Read \"stsc\" content failed");
    SAFE_DELETE_ARRAY(tmp);
    return -1;
  }

  uint32_t *p = (uint32_t *) tmp;
  first_chunk = new uint32_t[entry_count];
  sample_per_chunk = new uint32_t[entry_count];
  sample_description_index = new uint32_t[entry_count];
  for (uint32_t i = 0; i < entry_count; ++i) {
    first_chunk[i] = ENTOHL(*p);
    ++p;
    sample_per_chunk[i] = ENTOHL(*p);
    ++p;
    sample_description_index[i] = ENTOHL(*p);
    ++p;
  }

#ifdef XDEBUG
  printf("entry_count: %u\n", entry_count);
#if XDEBUG_FULL
  for (uint32_t i = 0; i < entry_count; ++i) {
    printf("first_chunk: %u\n", first_chunk[i]);
    printf("sample_per_chunk: %u\n", sample_per_chunk[i]);
    printf("sample_description_index: %u\n", sample_description_index[i]);
  }
#endif
#endif

  SAFE_DELETE_ARRAY(tmp);
  return 0;
}

/////////////////////////////////////////////////////////////

SampleSizeBox::SampleSizeBox(uint32_t _sz, uint32_t _typ,
                             uint8_t _ver, const uint24_t &_flgs) :
  FullBox(_sz, _typ, _ver, _flgs)
{
  entry_size = NULL;
}

SampleSizeBox::~SampleSizeBox()
{
  SAFE_DELETE_ARRAY(entry_size);
}

int SampleSizeBox::init(File *f)
{
  FullBox::print();

  /* REFERENCE
   * unsigned int(32) sample_size;
   * unsigned int(32) sample_count;
   * if (sample_size==0) {
   *     for (i=1; i <= sample_count; i++) {
   *         unsigned int(32) entry_size;
   *     }
   * }
   */
  if (!f->readui32(&sample_size, true)) {
    LOGE("Read \"stsz\" sample_size failed");
    return -1;
  }

  if (!f->readui32(&sample_count, true)) {
    LOGE("Read \"stsz\" sample_count failed");
    return -1;
  }

  if (!sample_size) {
    uint32_t tmp_len = sz - 12 - 8/*sample_size,sample_count's size*/;
    uint8_t *tmp = new uint8_t[tmp_len];
    if (!f->read_buffer(tmp, tmp_len)) {
      LOGE("Read \"stsz\" content failed");
      SAFE_DELETE_ARRAY(tmp);
      return -1;
    }

    uint32_t *p = (uint32_t *) tmp;
    entry_size = new uint32_t[sample_count];
    for (uint32_t i = 0; i < sample_count; ++i) {
      entry_size[i] = ENTOHL(*p);
      ++p;
    }

    SAFE_DELETE_ARRAY(tmp);
  }

#ifdef XDEBUG
  printf("sample_size: %u\n", sample_size);
  printf("sample_count: %u\n", sample_count);
#if XDEBUG_FULL
  if (!sample_size) {
    for (uint32_t i = 0; i < sample_count; ++i) {
      printf("entry_size: 0x%08x\n", entry_size[i]);
    }
  }
#endif
#endif

  return 0;
}

/////////////////////////////////////////////////////////////

ChunkOffsetBox::ChunkOffsetBox(uint32_t _sz, uint32_t _typ,
                               uint8_t _ver, const uint24_t &_flgs) :
  FullBox(_sz, _typ, _ver, _flgs)
{
  chunk_offset = NULL;
}

ChunkOffsetBox::~ChunkOffsetBox()
{
  SAFE_DELETE_ARRAY(chunk_offset);
}

int ChunkOffsetBox::init(File *f)
{
  FullBox::print();

  /* REFERENCE
   * unsigned int(32) entry_count;
   * for (i=1; i <= entry_count; i++) {
   *     unsigned int(32) chunk_offset;
   * }
   */
  if (!f->readui32(&entry_count, true)) {
    LOGE("Read \"stco\" entry_count failed");
    return -1;
  }

  uint32_t tmp_len = sz - 12 - 4;
  uint8_t *tmp = new uint8_t[tmp_len];
  if (!f->read_buffer(tmp, tmp_len)) {
    LOGE("Read \"stco\" content failed");
    SAFE_DELETE_ARRAY(tmp);
    return -1;
  }

  uint32_t *p = (uint32_t *) tmp;
  chunk_offset = new uint32_t[entry_count];
  for (uint32_t i = 0; i < entry_count; ++i) {
    chunk_offset[i] = ENTOHL(*p);
    ++p;
  }

#ifdef XDEBUG
  printf("entry_count: %u\n", entry_count);
#if XDEBUG_FULL
  for (uint32_t i = 0; i < entry_count; ++i) {
    printf("chunk_offset: 0x%08x\n", chunk_offset[i]);
  }
#endif
#endif

  SAFE_DELETE_ARRAY(tmp);
  return 0;
}

/////////////////////////////////////////////////////////////

ChunkLargeOffsetBox::ChunkLargeOffsetBox(uint32_t _sz, uint32_t _typ,
                                         uint8_t _ver, const uint24_t &_flgs) :
  FullBox(_sz, _typ, _ver, _flgs)
{
  chunk_offset = NULL;
}

ChunkLargeOffsetBox::~ChunkLargeOffsetBox()
{
  SAFE_DELETE_ARRAY(chunk_offset);
}

int ChunkLargeOffsetBox::init(File *f)
{
  FullBox::print();

  /* REFERENCE
   * unsigned int(32) entry_count;
   * for (i=1; i <= entry_count; i++) {
   *     unsigned int(64) chunk_offset;
   * }
   */
  if (!f->readui32(&entry_count, true)) {
    LOGE("Read \"co64\" entry_count failed");
    return -1;
  }

  uint32_t tmp_len = sz - 12 - 4;
  uint8_t *tmp = new uint8_t[tmp_len];
  if (!f->read_buffer(tmp, tmp_len)) {
    LOGE("Read \"co64\" content failed");
    SAFE_DELETE_ARRAY(tmp);
    return -1;
  }

  uint64_t *p = (uint64_t *) tmp;
  chunk_offset = new uint64_t[entry_count];
  for (uint32_t i = 0; i < entry_count; ++i) {
    chunk_offset[i] = ENTOHLL(*p);
    ++p;
  }

#ifdef XDEBUG
  printf("entry_count: %u\n", entry_count);
#if XDEBUG_FULL
  for (uint32_t i = 0; i < entry_count; ++i) {
    printf("chunk_offset: 0x%016lx\n", chunk_offset[i]);
  }
#endif
#endif

  SAFE_DELETE_ARRAY(tmp);
  return 0;
}

/////////////////////////////////////////////////////////////

mp4aBox::mp4aBox(uint32_t _sz, uint32_t _typ) :
  Box(_sz, _typ)
{
}

int mp4aBox::init(File *f)
{
  off_t cursave = f->cursor();

  /* REFERENCE
   * const unsigned int(8)[6] reserved = 0;
   * unsigned int(16) data_reference_index;
   * const unsigned int(32)[2] reserved = 0;
   * template unsigned int(16) channelcount = 2;
   * template unsigned int(16) samplesize = 16;
   * unsigned int(16) pre_defined = 0;
   * const unsigned int(16) reserved = 0 ;
   * template unsigned int(32) samplerate = {timescale of media}<<16;
   */
  for (int i = 0; i < 6; ++i) {
    if (!f->readui8(&reserved[i])) {
      LOGE("Read \"mp4a\" reserved[%d] failed", i);
      return -1;
    }
  }

  if (!f->readui16(&data_reference_index, true)) {
    LOGE("Read \"mp4a\" data_reference_index failed");
    return -1;
  }

  for (int i = 0; i < 2; ++i) {
    if (!f->readui32(&reserved1[i], true)) {
      LOGE("Read \"mp4a\" reserved1[%d] failed", i);
      return -1;
    }
  }

  if (!f->readui16(&channelcount, true)) {
    LOGE("Read \"mp4a\" channelcount failed");
    return -1;
  }

  if (!f->readui16(&samplesize, true)) {
    LOGE("Read \"mp4a\" samplesize failed");
    return -1;
  }

  if (!f->readui16(&pre_defined, true)) {
    LOGE("Read \"mp4a\" pre_defined failed");
    return -1;
  }

  if (!f->readui16(&reserved2, true)) {
    LOGE("Read \"mp4a\" reserved2 failed");
    return -1;
  }

  if (!f->readui32(&samplerate, true)) {
    LOGE("Read \"mp4a\" samplerate failed");
    return -1;
  }

#ifdef XDEBUG
  printf("reserved: { ");
  for (int i = 0; i < 6; ++i) {
    printf("%u ", reserved[i]);
  }
  printf("}\n");
  printf("data_reference_index: %u\n", data_reference_index);
  printf("reserved1: { ");
  for (int i = 0; i < 2; ++i) {
    printf("%u ", reserved1[i]);
  }
  printf("}\n");
  printf("channelcount: %u\n", channelcount);
  printf("samplesize: %u\n", samplesize);
  printf("pre_defined: %u\n", pre_defined);
  printf("reserved: %u\n", reserved2);
  printf("samplerate: %u\n", samplerate);
#endif

  return parse_box(sub, f, (f->cursor() - cursave) + sz - 8);
}

/////////////////////////////////////////////////////////////

esdsBox::esdsBox(uint32_t _sz, uint32_t _typ,
                 uint8_t _ver, const uint24_t &_flgs) :
  FullBox(_sz, _typ, _ver, _flgs),
  to_confirm(false),
  audio_object_type(0),
  samplerate_idx(0),
  channel(0)
{
}

static uint32_t mp4_descr_length(byte *&p)
{
  uint8_t b;
  uint8_t num_bytes = 0;
  uint32_t length = 0;

  do {
    b = *p++;
    ++num_bytes;
    length = (length<<7)|(b&0x7F);
  } while ((b&0x80) && num_bytes<4);

  return length;
}

int esdsBox::init(File *f)
{
  off_t cursave = f->cursor();

  FullBox::print();

  uint32_t content_len = sz - 12;
  uint8_t *tmp = new uint8_t[content_len], *p = tmp;
  if (!f->read_buffer(tmp, content_len)) {
    LOGE("Read \"esds\" content failed");
    return -1;
  }

  uint32_t len;

  // Verify ES_DescrTag
  byte tag = *p++;
  if (tag == 0x03) {
    // Read length
    if (mp4_descr_length(p) < 5 + 15) {
      LOGE("mp4_descr_length for tag 0x03 failed");
      goto out;
    }

    // Skip 3 bytes
    p += 3;
  } else {
    // Skip 2 bytes
    p += 2;
  }

  // Verify DecoderConfigDescrTab
  tag = *p++;
  if (tag != 0x04) {
    LOGE("Verify DecoderConfigDescrTab failed");
    goto out;
  }

  // Read length
  if (mp4_descr_length(p) < 13) {
    LOGE("mp4_descr_length for tag 0x04 failed");
    goto out;
  }

  // Skip 1byte of audio_type
  p += 1;

  // Skip 4 bytes
  p += 4;

  // Skip 4 bytes for max_bitrate
  p += 4;

  // Skip 4 bytes for avg_bitrate
  p += 4;

  // Verify DecSpecificInfoTag
  tag = *p++;
  if (tag != 0x05) {
    LOGE("Verify DecSpecificInfoTag failed");
    goto out;
  }

  len = mp4_descr_length(p);
  if (len > 0) {
    len *= 8; // Count the number of bits left
    audio_object_type = (*p&0xF8)>>3; // Get 5 bits
    len -= 5;

    if (audio_object_type == 0x1F) {
      LOGW("This type of esds box is not supported");
      goto out;
    }

    {
      // Get 4bits samplerate
      samplerate_idx = (*p&0x07)<<1;
      samplerate_idx |= (*++p&0x80);
      len -= 4;

      if (samplerate_idx != 0xF) {
        // Get 4bits channel
        channel = ((*p&0x78)>>3);
        len -= 4;

        // Skip rest of bits
        len -= 3;
        p += len/8 + 1;
      }
    }
  }

  // Verify SL config descriptor type tag
  tag = *p++;
  if (tag != 0x06) {
    LOGE("Verify SL config descriptor type tag failed");
    goto out;
  }

  mp4_descr_length(p);

  // Verify SL value
  tag = *p++;
  if (tag != 0x02) {
    LOGE("Verify SL value failed");
    goto out;
  }

  // Generate AudioSpecificConfig
  generate_asc(asc,
      audio_object_type, samplerate_idx, channel);
#ifdef XDEBUG
  print_asc(asc);
#endif

out:
  SAFE_DELETE_ARRAY(tmp);
  uint32_t skipped_bytes = sz - (f->cursor() - cursave) - 12;
  if (skipped_bytes) {
    // Error occurred while parsing esds, generate asc later
    to_confirm = true;
    return f->seek_ahead(skipped_bytes) ? 0 : -1;
  }
  return 0;
}

/////////////////////////////////////////////////////////////

EditBox::EditBox(uint32_t _sz, uint32_t _typ) :
  Box(_sz, _typ)
{
}

int EditBox::init(File *f)
{
  return parse_box(sub, f, f->cursor() + sz - 8);
}

/////////////////////////////////////////////////////////////

EditListBox::EditListBox(uint32_t _sz, uint32_t _typ,
                         uint8_t _ver, const uint24_t &_flgs) :
  FullBox(_sz, _typ, _ver, _flgs) ,
  elst_entry(NULL)
{
}

EditListBox::~EditListBox()
{
  SAFE_DELETE_ARRAY(elst_entry);
}

int EditListBox::init(File *f)
{
  FullBox::print();

  /* REFERENCE
   * unsigned int(32) entry_count; 
   * for (i=1; i <= entry_count; i++) { 
   *     if (version==1) { 
   *         unsigned int(64) segment_duration; 
   *         int(64) media_time; 
   *     } else { // version==0 
   *         unsigned int(32) segment_duration; 
   *         int(32) media_time; 
   *     } 
   *     int(16) media_rate_integer; 
   *     int(16) media_rate_fraction = 0; 
   * }
   */

  if (!f->readui32(&entry_count, true)) {
    LOGE("Read \"elst\" entry_count failed");
    return -1;
  }

  elst_entry = new ELSTEntry[entry_count];
  for (uint32_t i = 0; i < entry_count; ++i) {
    if (ver == 1) {
      if (!f->readui64(&elst_entry[i].segment_duration.u64, true)) {
        LOGE("Read \"elst\" %u:segment_duration(64) failed", i);
        return -1;
      }

      if (!f->readi64(&elst_entry[i].media_time.i64, true)) {
        LOGE("Read \"elst\" %u:media_time(64) failed", i);
        return -1;
      }
    } else { // ver == 0
      if (!f->readui32(&elst_entry[i].segment_duration.u32, true)) {
        LOGE("Read \"elst\" %u:segment_duration failed", i);
        return -1;
      }

      if (!f->readi32(&elst_entry[i].media_time.i32, true)) {
        LOGE("Read \"elst\" %u:media_time failed", i);
        return -1;
      }
    }

    if (!f->readi16(&elst_entry[i].media_rate_integer, true)) {
      LOGE("Read \"elst\" media_rate_integer failed");
      return -1;
    }

    if (!f->readi16(&elst_entry[i].media_rate_fraction, true)) {
      LOGE("Read \"elst\" media_rate_fraction failed");
      return -1;
    }
  }

#ifdef XDEBUG
  printf("entry_count: %u\n", entry_count);
  for (uint32_t i = 0; i < entry_count; ++i) {
    printf("entry: %u ===>\n", i);
    if (ver == 1) {
      printf("segment_duration: %llu\n",
             (unsigned long long) elst_entry[i].segment_duration.u64);
      printf("media_time: %lld\n",
             (long long) elst_entry[i].media_time.i64);
    } else {
      printf("segment_duration: %u\n",
             elst_entry[i].segment_duration.u32);
      printf("media_time: %d\n",
             elst_entry[i].media_time.i32);
    }
    printf("media_rate_integer: %d\n", elst_entry[i].media_rate_integer);
    printf("media_rate_fraction: %d\n", elst_entry[i].media_rate_fraction);
  }
#endif

  return 0;
}

}
