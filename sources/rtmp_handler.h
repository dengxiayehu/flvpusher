#ifndef _RTMP_HANDLER_H_
#define _RTMP_HANDLER_H_

#include <string>
#include <librtmp/rtmp.h>
#include <xutil.h>

#include "flv_muxer.h"

namespace flvpusher {

class VideoRawParser;
class AudioRawParser;

class RtmpHandler {
public:
    RtmpHandler(const std::string &flvpath);
    ~RtmpHandler();

    int connect(const std::string &liveurl);
    int disconnect();

    int send_video(int32_t timestamp, byte *dat, uint32_t length);
    int send_audio(int32_t timestamp, byte *dat, uint32_t length);

    bool send_rtmp_pkt(int pkttype, uint32_t ts,
                       const byte *buf, uint32_t pktsize);

private:
    struct DataInfo {
        int32_t lts; // Last timestamp
        int32_t tm_offset;
        bool need_cfg; // Either need to send asc or avc_dcr

        DataInfo() :
            lts(0), tm_offset(0), need_cfg(true) { }
    };

    enum RTMPPacketSize {
        RTMP_PS_TWELVEBYTES = 0,
        RTMP_PS_EIGHTBYTES,
        RTMP_PS_FOURBYTES,
        RTMP_PS_ONEBYTE
    };

    struct RTMPPacket {
        int channel_id;
        int type;
        uint32_t timestamp;
        uint32_t ts_field;
        uint32_t extra;
        uint8_t *data;
        int size;
        int offset;
        int read;
    };

    struct RTMPContext {
        RTMPPacket *prev_pkt[2];
        int nb_prev_pkt[2];
        RTMP *rtmp;
        RTMPPacket out_pkt;
        volatile int quit;
    };

private:
    static int make_asc_body(const byte asc[], byte buf[], uint32_t len);
    static int make_audio_body(const byte *dat, uint32_t dat_len,
                               byte buf[], uint32_t len);

    static int make_avc_dcr_body(byte *buf,
            const byte *sps, uint32_t sps_len,
            const byte *pps, uint32_t pps_len);
    static int make_video_body(byte *buf, uint32_t dat_len,
            bool key_frame);

    static byte pkttyp2channel(byte typ);

    static int rtmp_check_alloc_array(RTMPPacket **prev_pkt, int *nb_prev_pkt,
                                      int channel);
    static int rtmp_packet_create(RTMPPacket *pkt, int channel_id, int type,
                                  int timestamp, int size);
    static int rtmp_send_packet(RTMPContext *rt, RTMPPacket *pkt, int track);
    static void rtmp_packet_destroy(RTMPPacket *pkt);
    static int rtmp_packet_write(RTMPContext *rt, RTMPPacket *pkt, int chunk_size,
                                 RTMPPacket **prev_pkt_ptr, int *nb_prev_pkt);
    static int send_to_network(RTMPContext *rt, const uint8_t *buf, int size);

private:
    RTMPContext m_rt;
    std::string m_url;

    VideoRawParser *m_vparser;
    AudioRawParser *m_aparser;
    FLVMuxer m_flvmuxer;

    DataInfo m_vinfo;
    DataInfo m_ainfo;

    xutil::MemHolder m_mem_holder;
};

}

#endif /* end of _RTMP_HANDLER_H_ */
