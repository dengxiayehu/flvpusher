#include "hls_common.h"

#include <dirent.h>
#include <xlog.h>
#include <xfile.h>

using namespace xutil;
using namespace std;

namespace flvpusher {

bool valid_m3u8(const string &filename)
{
    if (is_file(filename)) {
        xfile::File file;
        if (file.open(STR(filename), "r")) {
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

bool complete_m3u8(const string &filename)
{
    if (valid_m3u8(STR(filename))) {
        xfile::File file;
        if (file.open(STR(filename), "r")) {
            char line[1024];
            while (file.read_line(line, sizeof(line))) {
                if (!strncasecmp(line, "#EXTINF", 7))
                    break;
            }
            if (!file.eof()) {
                if (file.read_line(line, sizeof(line))) {
                    char *p = line;
                    while (!(*p >= '0' && *p <= '9')) ++p;
                    char *q = p;
                    while (*q >= '0' && *q <= '9') ++q;
                    *q = '\0';
                    if (atoi(p) == 0)
                        return true;
                }
            }
        }
    }
    return false;
}

bool has_complete_m3u8(const string &dir)
{
    DIR *pdir = opendir(STR(dir));
    if (!pdir) {
        LOGE("opendir \"%s\" failed: %s", STR(dir), ERRNOMSG);
        return false;
    }
    bool retval = false;
    struct dirent *ent;
    while ((ent = readdir(pdir)) != NULL) {
        if (ent->d_type & DT_DIR)
            continue;

        if (end_with(ent->d_name, ".m3u8")) {
            string m3u8_abspath =
                sprintf_("%s/%s", STR(dir), ent->d_name);
            if (complete_m3u8(m3u8_abspath)) {
                retval = true;
                break;
            }
        }
    }
    closedir(pdir);
    return retval;
}

}
