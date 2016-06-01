#ifndef _HLS_COMMON_H_
#define _HLS_COMMON_H_

#include <string>

namespace flvpusher {

bool valid_m3u8(const std::string &filename);
bool complete_m3u8(const std::string &filename);
bool has_complete_m3u8(const std::string &dir);

}

#endif /* end of _HLS_COMMON_H_ */
