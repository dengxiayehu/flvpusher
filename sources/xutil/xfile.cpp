#include "xfile.h"
#include "xlog.h"

using namespace xutil;

namespace xfile {

File::File() :
  m_fp(NULL),
  m_filesz(0)
{
}

File::~File()
{
  this->close();
}

bool File::open(const std::string &path, const char *mode)
{
  close();

  if (path.empty() || !mode) {
    LOGE("Empty path or NULL mode passed (%s:%s)", path.c_str(), mode);
    return false;
  }

  m_fp = fopen(path.c_str(), mode);
  if (!m_fp) {
    LOGE("fopen file \"%s\" failed: %s",
         path.c_str(), ERRNOMSG);
    return false;
  }

  if (!seek_end()) {
    close();
    return false;
  }

  m_filesz = cursor();
  m_path = path;

  if (!seek_begin()) {
    close();
    return false;
  }

  return true;
}

void File::close()
{
  if (m_fp) {
    fclose(m_fp);
    m_fp = NULL;
  }

  m_path = "";
  m_filesz = 0;
}

off_t File::cursor() const
{
  off_t cus = ftello(m_fp);
  if (cus < 0) {
    fprintf(stderr, "ftello failed: %s\n",
            ERRNOMSG);
    return -1;
  }
  return cus;
}

bool File::seek_ahead(off_t cnt) const
{
  if (cnt < 0) {
    LOGE("Invalid offset %d passed", cnt);
    return false;
  }

  if (!cnt)
    return true;

  if (cursor() + cnt > size()) {
    LOGE("Dest pos exceeds file end");
    return false;
  }

  if (fseeko(m_fp, cnt, SEEK_CUR) < 0) {
    LOGE("Unable to seek ahead %ld bytes: %s",
         cnt, ERRNOMSG);
    return false;
  }

  return true;
}

bool File::seek_behind(off_t cnt) const
{
  if (cnt < 0) {
    LOGE("Invalid offset %d passed", cnt);
    return false;
  }

  if (!cnt)
    return true;

  if (cursor() < cnt) {
    LOGE("Dest pos rewind exceeds begin");
    return false;
  }

  if (fseeko(m_fp, (-1) * cnt, SEEK_CUR) < 0) {
    LOGE("Unable to seek behind %ld bytes: %s",
         cnt, ERRNOMSG);
    return false;
  }

  return true;
}

bool File::seek_to(off_t pos) const
{
  if (fseeko(m_fp, pos, SEEK_SET) < 0) {
    LOGE("Unable to seek position %ld", pos);
    return false;
  }

  return true;
}

bool File::seek_begin() const
{
  if (fseeko(m_fp, 0, SEEK_SET) < 0) {
    LOGE("Seek to the beginning failed: %s", ERRNOMSG);
    return false;
  }

  return true;
}

bool File::seek_end() const
{
  if (fseeko(m_fp, 0, SEEK_END) < 0) {
    LOGE("Seek to the end of file failed: %s", ERRNOMSG);
    return false;
  }

  return true;
}

bool File::readi8(int8_t *val) const
{
  return read_buffer(reinterpret_cast<uint8_t *>(val), 1);
}

bool File::readi16(int16_t *val, bool net_order) const
{
  if (read_buffer(reinterpret_cast<uint8_t *>(val), 2)) {
    if (net_order)
      *val = ENTOHS(*val);

    return true;
  }

  return false;
}

bool File::readi24(int32_t *val, bool net_order) const
{
  if (read_buffer(reinterpret_cast<uint8_t *>(val), 3)) {
    if (net_order)
      *val = (ENTOHL(*val) >> 8);

    return true;
  }

  return false;
}

bool File::readi32(int32_t *val, bool net_order) const
{
  if (read_buffer(reinterpret_cast<uint8_t *>(val), 4)) {
    if (net_order)
      *val = ENTOHL(*val);

    return true;
  }

  return false;
}

bool File::readi64(int64_t *val, bool net_order) const
{
  if (read_buffer(reinterpret_cast<uint8_t *>(val), 8)) {
    if (net_order)
      *val = ENTOHLL(*val);

    return true;
  }

  return false;
}

bool File::readui8(uint8_t *val) const
{
  return readi8(reinterpret_cast<int8_t *>(val));
}

bool File::readui16(uint16_t *val, bool net_order) const
{
  return readi16(reinterpret_cast<int16_t *>(val), net_order);
}

bool File::readui24(uint32_t *val, bool net_order) const
{
  return readi24(reinterpret_cast<int32_t *>(val), net_order);
}

bool File::readui32(uint32_t *val, bool net_order) const
{
  return readi32(reinterpret_cast<int32_t *>(val), net_order);
}

bool File::readui64(uint64_t *val, bool net_order) const
{
  return readi64(reinterpret_cast<int64_t *>(val), net_order);
}

bool File::read_buffer(uint8_t *buf, size_t sz) const
{
  if (fread(buf, sz, 1, m_fp) < 1) {
    if (ferror(m_fp)) {
      LOGE("Unable to read %lu bytes to buffer: %s",
           sz, ERRNOMSG);
      return false;
    }

    if (feof(m_fp)) {
      return false;
    }

    // Neither of them, see whether |sz| is zero
    if (sz == 0) {
      //LOGW("Try to read 0 bytes from file");
      return true;
    }

    LOGW("fread returned 0 unexpectedly");
    return false;
  }

  return true;
}

bool File::read_line(char *s, size_t sz) const
{
  return !!fgets(s, sz, m_fp);
}

bool File::writei8(int8_t val) const
{
  return write_buffer(reinterpret_cast<uint8_t *>(&val), 1);
}

bool File::writei16(int16_t val, bool net_order) const
{
  if (net_order)
    val = EHTONS(val);

  return write_buffer(reinterpret_cast<uint8_t *>(&val), 2);
}

bool File::writei24(int32_t val, bool net_order) const
{
  if (net_order)
    val = EHTONL(val << 8);

  return write_buffer(reinterpret_cast<uint8_t *>(&val), 3);
}

bool File::writei32(int32_t val, bool net_order) const
{
  if (net_order)
    val = EHTONL(val);

  return write_buffer(reinterpret_cast<uint8_t *>(&val), 4);
}

bool File::writei64(int64_t val, bool net_order) const
{
  if (net_order)
    val = EHTONLL(val);

  return write_buffer(reinterpret_cast<uint8_t *>(&val), 8);
}

bool File::writeui8(uint8_t val) const
{
  return writei8(static_cast<int8_t>(val));
}

bool File::writeui16(uint16_t val, bool net_order) const
{
  return writei16(static_cast<int16_t>(val), net_order);
}

bool File::writeui24(uint32_t val, bool net_order) const
{
  return writei24(static_cast<int32_t>(val), net_order);
}

bool File::writeui32(uint32_t val, bool net_order) const
{
  return writei32(static_cast<int32_t>(val), net_order);
}

bool File::writeui64(uint64_t val, bool net_order) const
{
  return writei64(static_cast<int64_t>(val), net_order);
}

bool File::write_string(const char *val) const
{
  return write_buffer(
      reinterpret_cast<const uint8_t *>(val), strlen(val));
}

bool File::write_buffer(const uint8_t *buffer, long len) const
{
  if (len == 0)
    return true;

  if (fwrite(buffer, len, 1, m_fp) < 1) {
    if (ferror(m_fp)) {
      LOGE("Unable to write %ld bytes to file: %s",
           len, ERRNOMSG);

      return false;
    }
  }

  m_filesz = ftello(m_fp);
  return true;
}

bool File::flush()
{
  if (m_fp) {
    fflush(m_fp);

    off_t curpos = cursor();

    if (!seek_end()) {
      return false;
    }

    m_filesz = ftello(m_fp);

    if (!seek_to(curpos)) {
      return false;
    }
  }

  return true;
}

std::string File::read_content(const std::string &path)
{
  File file;
  if (!file.open(STR(path), "rb"))
    return "";
  uint8_t *buf = (uint8_t *) calloc(1, file.size() + 1);
  if (!buf) {
    LOGE("malloc for file(\"%s\")'s content failed: %s",
         STR(path), ERRNOMSG);
    return "";
  }
  if (!file.read_buffer(buf, file.size())) {
    SAFE_FREE(buf);
    return "";
  }
  std::string res((char *) buf);
  SAFE_FREE(buf);
  return res;
}

int File::flush_content(const std::string &path, const uint8_t *buf, int buf_size, const char *mode)
{
  File file;
  if (!file.open(STR(path), mode)) {
    LOGE("Open file(\"%s\") failed", STR(path));
    return -1;
  }
  if (buf && buf_size && !file.write_buffer(buf, buf_size)) {
    LOGE("Write content to file(\"%s\") failed", STR(path));
    return -1;
  }
  file.close();
  return 0;
}

}
