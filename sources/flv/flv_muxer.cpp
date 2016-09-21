#include "flv_muxer.h"

#include <librtmp/rtmp.h>

using namespace xutil;

namespace flvpusher {

FLVMuxer::FLVMuxer() :
  m_file(NULL), m_tm_offset(-1)
{
    m_file = new xfile::File;
}

FLVMuxer::~FLVMuxer()
{
  SAFE_DELETE(m_file);
}

int FLVMuxer::set_file(const std::string &flvpath)
{
  if (!m_file->open(flvpath, "wb"))
    return -1;

  m_file->write_string("FLV");
  m_file->writeui8(1);
  m_file->writeui8(0x04 + 0x01);
  m_file->writeui32(0x09, true);
  m_file->writeui32(0x0);
  return 0;
}

bool FLVMuxer::is_opened() const
{
  return m_file && m_file->is_opened();
}

const char *FLVMuxer::get_path() const
{
  if (is_opened()) {
    return m_file->get_path();
  }
  return "";
}

int FLVMuxer::write_tag(int typ, int ts, const uint8_t *buf, int buf_size)
{
  if (typ != RTMP_PACKET_TYPE_VIDEO &&
      typ != RTMP_PACKET_TYPE_AUDIO &&
      typ != RTMP_PACKET_TYPE_INFO)
    return 0;

  if (m_tm_offset == -1) {
    m_tm_offset = -ts;
  }
  ts += m_tm_offset;

  m_file->writeui8(typ);
  m_file->writeui24(buf_size, true);
  m_file->writeui24(ts&0xFFFFFF, true);
  m_file->writeui8(ts&0xFF000000);
  m_file->writeui24(0, true);
  m_file->write_buffer(buf, buf_size);
  m_file->writeui32(buf_size+11, true);
  return 0;
}

}
