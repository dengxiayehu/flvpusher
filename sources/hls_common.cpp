#include "hls_common.h"

#include <xfile.h>

using namespace std;
using namespace xutil;

namespace flvpusher {

bool valid_vod_m3u8(const string &filename)
{
    if (is_file(filename)) {
        xfile::File file;
        if (file.open(STR(filename), "r")) {
            if (file.size() < 7)
                return false;

            const char *m3u8_endline = "#EXT-X-ENDLIST";
            const int endline_len = strlen(m3u8_endline);
            if (file.seek_to(file.size() - endline_len)) {
                char buf[128];
                if (file.read_buffer((uint8_t *) buf, endline_len))
                    if (!strncmp(buf, m3u8_endline, endline_len))
                        return true;
            }
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
