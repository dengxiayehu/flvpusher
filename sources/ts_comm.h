#ifndef _TS_COMM_H_
#define _TS_COMM_H_

// pids
#define PAT_PID     0x0000
#define SDT_PID     0x0011

// table ids
#define PAT_TID   0x00
#define PMT_TID   0x02
#define SDT_TID   0x42

#define TS_FEC_PACKET_SIZE 204
#define TS_DVHS_PACKET_SIZE 192
#define TS_PACKET_SIZE  188
#define TS_MAX_PACKET_SIZE 204

#define NB_PID_MAX 8192
#define MAX_SECTION_SIZE 4096

#define MAX_PIDS_PER_PROGRAM 64

// Enough for PES header + length
#define PES_START_SIZE  6 
#define PES_HEADER_SIZE 9
#define MAX_PES_HEADER_SIZE (9 + 255)

#define MAX_PES_PAYLOAD 200 * 1024

#define STREAM_TYPE_AUDIO_AAC       0x0f
#define STREAM_TYPE_VIDEO_H264      0x1b

#endif /* end of _TS_COMM_H_ */
