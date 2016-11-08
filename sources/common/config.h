#ifndef _CONFIG_H_
#define _CONFIG_H_

extern char abs_program[];

#define VERSION_STR             "20161108.0.1"

#define INPUT_SEPARATOR         ","

#define LOG_DIR                 "/tmp/"

#define SOCK_TIMEOUT            30 // seconds
#define RTMP_LOGLEVEL           RTMP_LOGDEBUG
#define RTMP_DEF_BUFTIME        (10*60*60*1000) // 10 hours default
#define RTMP_MAX_PLAY_BUFSIZE   (10*1024*1024)  // 10M
#define RTMP_SEND_FFMPEG        1

#define NEW_STREAM_TIMESTAMP_THESHO     300

#define DEFAULT_CFG_FILE                "./flvpusher_cfg.txt"

#define DEFAULT_CURL_HLS_TIMEOUT        20
#define DEFAULT_CURL_HEARTBEAT_INTERVAL 60

#define DEFAULT_LISTEN_PORT         9877
#define DEFAULT_SERVER_THREADS      5
#define DEFAULT_DOCUMENT_ROOT       "./html"

#define DEFAULT_HLS_INFO_FILE       "hls_info.txt"

#define DEFAULT_WAIT_SEGMENT_DONE   20

#define DEFAULT_HLS_EXPIRE_TIME     259200
#define DEFAULT_HLS_SCAN_INTERVAL   43200

#define RTSP_SINK_BUFFERING_TIME_AFTER_KEY_FRAME    500 // ms

#endif /* end of _CONFIG_H_ */
