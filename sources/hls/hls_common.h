#ifndef _HLS_COMMON_H_
#define _HLS_COMMON_H_

#include <stdint.h>

#include <string>

namespace flvpusher {

bool is_valid_vod_m3u8(const std::string& filename);
bool is_valid_m3u8(const uint8_t* buf, size_t size);

}  // namespace flvpusher

#endif /* end of _HLS_COMMON_H_ */
