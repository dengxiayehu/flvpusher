#ifndef _CONFIG_H_
#define _CONFIG_H_

#define VERSION                 2

#define INPUT_SEPARATOR         ","

#define LOG_DIR                 "/tmp/"

#define SOCK_TIMEOUT            30 // seconds
#define RTMP_LOGLEVEL           RTMP_LOGDEBUG
#define RTMP_DEF_BUFTIME        (10*60*60*1000) // 10 hours default
#define RTMP_MAX_PLAY_BUFSIZE   (10*1024*1024) // 10M
#define RTMP_CHUNK_SIZE         2048

#define NEW_STREAM_TIMESTAMP_THESHO 300

#define HLS_LOCK_FILENAME       "hls_lock.txt"

#endif /* end of _CONFIG_H_ */
