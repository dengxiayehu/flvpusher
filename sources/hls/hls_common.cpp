#include <memory>
#include <xfile.h>

#include "hls_common.h"

using namespace std;
using namespace xutil;

namespace flvpusher {

bool is_valid_vod_m3u8(const string &filename)
{
  if (is_file(filename)) {
    std::auto_ptr<IOBuffer> iobuf(new IOBuffer);
    iobuf->read_from_file(filename, "r");
    if (is_valid_m3u8(GETIBPOINTER(*iobuf), GETAVAILABLEBYTESCOUNT(*iobuf))) {
      const char *m3u8_endline = "#EXT-X-ENDLIST";
      const int endline_len = strlen(m3u8_endline);
      iobuf->ignore(GETAVAILABLEBYTESCOUNT(*iobuf) - endline_len);
      if (!strncmp((const char *) GETIBPOINTER(*iobuf), m3u8_endline,
                   endline_len))
        return true;
    }
  }
  return false;
}

bool is_valid_m3u8(const uint8_t *buf, size_t size)
{
  if (!buf || size < 7)
    return false;

  if (memcmp(buf, "#EXTM3U", 7) != 0)
    return false;

  buf += 7;
  size -= 7;

  while (size--) {
    static const char *const ext[] = {
      "TARGETDURATION",
      "MEDIA-SEQUENCE",
      "KEY",
      "ALLOW-CACHE",
      "ENDLIST",
      "STREAM-INF",
      "DISCONTINUITY",
      "VERSION"
    };

    if (*buf++ != '#')
      continue;

    if (size < 6)
      continue;

    if (memcmp(buf, "EXT-X-", 6))
      continue;

    buf += 6;
    size -= 6;

    for (size_t i = 0; i < NELEM(ext); ++i) {
      size_t len = strlen(ext[i]);
      if (size < 0 || (size_t) size < len)
        continue;
      if (!memcmp(buf, ext[i], len))
        return true;
    }
  }

  return false;
}

}
