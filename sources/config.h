#ifndef _CONFIG_H_
#define _CONFIG_H_

extern char abs_program[];

#define VERSION                 2

#define INPUT_SEPARATOR         ","

#define LOG_DIR                 "/tmp/"

#define SOCK_TIMEOUT            30 // seconds
#define RTMP_LOGLEVEL           RTMP_LOGDEBUG
#define RTMP_DEF_BUFTIME        (10*60*60*1000) // 10 hours default
#define RTMP_MAX_PLAY_BUFSIZE   (10*1024*1024)  // 10M

#define NEW_STREAM_TIMESTAMP_THESHO 300

#define DEFAULT_CFG_FILE            "./flvpusher_cfg.txt"

#define DEFAULT_CURL_HLS_TIMEOUT    20

#define DEFAULT_LISTEN_PORT         9877
#define DEFAULT_SERVER_THREADS      5
#define DEFAULT_DOCUMENT_ROOT       "./html"

#define DEFAULT_HLS_LOCK_FILE       "hls_lock.txt"

#endif /* end of _CONFIG_H_ */
