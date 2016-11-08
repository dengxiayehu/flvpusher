#include "tag_streamer.h"

#include <amf.h>

//#define XDEBUG

using namespace amf;

namespace flvpusher {

TagStreamerBase::TagStreamerBase(const std::string &dump_path) :
  m_strm_len(0)
{
  if (!dump_path.empty())
    set_dump_path(dump_path);
}

TagStreamerBase::~TagStreamerBase()
{
  m_file.close();
}

int TagStreamerBase::set_dump_path(const std::string &path)
{
  if (m_file.is_opened())
    m_file.close();

  return m_file.open(path.c_str(), "wb+");
}

byte *TagStreamerBase::get_strm() const
{
  return (byte *) m_mem_holder.get_buffer();
}

uint32_t TagStreamerBase::get_strm_length () const
{
  return m_strm_len;
}

/////////////////////////////////////////////////////////////

int VideoTagStreamer::process(FLVParser::FLVTag &tag)
{
  if (tag.hdr.typ != FLVParser::TAG_VIDEO)
    return 0; // Not video tag, return

  m_strm_len = 0;

  FLVParser::FLVVideoTagData &vdat = tag.dat.video;

  if (vdat.codec_id == FLVParser::CODECID_H264) {
    switch (vdat.pkt.pkt_typ) {
      case FLVParser::SEQUENCE_HEADER: {
        // Store sps & ppS
        m_sps_len = vdat.pkt.avc_dcr.sps_length;
        memcpy(m_sps, vdat.pkt.avc_dcr.sps, m_sps_len);

        m_pps_len = vdat.pkt.avc_dcr.pps_length;
        memcpy(m_pps, vdat.pkt.avc_dcr.pps, m_pps_len);
      } break;

      case FLVParser::NALU: {
        bool key_frame = false;

        /* First figure out how much space we need 
         * 4bytes for nalu_startcode */
        FOR_VECTOR_ITERATOR(NaluItem *, *vdat.pkt.nalu.dat, it) {
          m_strm_len += 4 + (*it)->first;

          // To see whether this is a key frame
          if (!key_frame) {
            /* Some video stream still has startcode left, take care */
            byte nalu_type;
            if (STARTCODE4((*it)->second))
              nalu_type = (*it)->second[4]&0x1F;
            else if (STARTCODE3((*it)->second))
              nalu_type = (*it)->second[3]&0x1F;
            else
              nalu_type = (*it)->second[0]&0x1F;

            // Take these as I-frame's beginning
            if (nalu_type == 5 /*IDR*/ ||
                nalu_type == 7 /*SPS*/ || nalu_type == 8 /*PPS*/) {
              key_frame = true;
#ifdef XDEBUG
              LOGD("KeyFrame detected, nalu type: %d, timestamp: %d",
                   nalu_type, VALUI24(tag.hdr.timestamp));
#endif
            }
          }
        }

        if (key_frame) {
          // If is key frame, add sps & pps before nalus
          m_strm_len += 4 + m_sps_len + 4 + m_pps_len;
        }

        byte *dat = (byte *) m_mem_holder.alloc(m_strm_len);
        uint32_t offset = 0;

        if (key_frame) {
          // First sps & pps
          memcpy(dat, nalu_startcode, 4);
          memcpy(dat+4, m_sps, m_sps_len);
          memcpy(dat+4+m_sps_len, nalu_startcode, 4);
          memcpy(dat+4+m_sps_len+4, m_pps, m_pps_len);

          offset = 4 + m_sps_len + 4 + m_pps_len;
        }

        FOR_VECTOR_ITERATOR(NaluItem *, *vdat.pkt.nalu.dat, it) {
          // Add nalu_startcode
          memcpy(dat+offset,
                 nalu_startcode, sizeof(nalu_startcode));
          offset += 4;

          // Nalu data followed
          memcpy(dat+offset, (*it)->second, (*it)->first);
          offset += (*it)->first;
        }
      } break;

      case FLVParser::END_OF_SEQUENCE:
        // No need to deal with END_OF_SEQUENCE, fall through
      default:
        return 0;
    }

  } else {
    // Video codec not supported, fall through
    return -1;
  }

  // Write to file if needs
  if (m_file.is_opened()) {
    if (!m_file.write_buffer(get_strm(), m_strm_len)) {
      LOGE("Write video data to file failed");
      // Fall through
    }
  }
  return 0;
}

/////////////////////////////////////////////////////////////

int AudioTagStreamer::process(FLVParser::FLVTag &tag)
{
  if (tag.hdr.typ != FLVParser::TAG_AUDIO)
    return 0; // Not audio tag, return

  FLVParser::FLVAudioTagData &adat = tag.dat.audio;

  m_strm_len = 0;

  if (adat.sound_fmt == 10 /* AAC */) {
    if (adat.aac.typ == 0 /* asc */) {
      memcpy(m_asc.dat, adat.aac.asc.dat, 2);
    } else if (adat.aac.typ == 1 /* aac raw */) {
      m_strm_len = 7 + adat.aac.dat.length;
      byte *dat = (byte *) m_mem_holder.alloc(m_strm_len);
      // Generate adts header
      if (generate_adts_header(m_asc, adat.aac.dat.length, dat) < 0) {
        m_strm_len = 0;
        return -1;
      }

      // Copy rest aac raw data
      memcpy(dat+7, adat.aac.dat.strm, adat.aac.dat.length);
    } else {
      // fall through
    }

  } else {
    // Not supported sound-fomat, fall through
  }

  // Write to file if needs
  if (m_file.is_opened()) {
    if (!m_file.write_buffer(get_strm(), m_strm_len)) {
      LOGE("Write audio data to file failed");
      // Fall through
    }
  }
  return 0;
}

/////////////////////////////////////////////////////////////

int ScriptTagStreamer::process(FLVParser::FLVTag &tag)
{
  // Alloc enough buffer for streamed script
  byte *p =
    (byte *) m_mem_holder.alloc(VALUI24(tag.hdr.datasize));

  if (strm_amf_list(p, &tag.dat.script) < 0) {
    LOGE("Stream script failed");
    return -1;
  }

  // Update streamed script size
  m_strm_len = p - (byte *) m_mem_holder.get_buffer();

#ifdef XDEBUG
  if (m_strm_len != VALUI24(tag.hdr.datasize)) {
    LOGW("Stream script failed (ignored)");
  }
#endif
  return 0;
}

}
