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

}
