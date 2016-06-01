#ifndef _TS_MUXER_H_
#define _TS_MUXER_H_

#include <ffmpeg.h>
#include <xfile.h>

#define MPEGTS_FLAG_REEMIT_PAT_PMT  0x01
#define MPEGTS_FLAG_AAC_LATM        0x02

using namespace ffmpeg;

namespace flvpusher {

class TSMuxer {
public:
    TSMuxer();
    ~TSMuxer();

    int set_file(const std::string &tspath, AVRational itime_base);

    int write_frame(const int32_t ts,
            const uint8_t *dat, const uint32_t dat_len, int is_video);

    bool is_opened() const;

    off_t size() const;

private:
    enum { VIDEO, AUDIO, STRM_NUM };

    struct TSSection {
        int pid;
        int cc;
        void (*write_packet) (struct TSSection *s, const uint8_t *packet);
        void *opaque;
    };

    struct TSService {
        TSSection pmt;
        int sid;
        char *name;
        char *provider_name;
        int pcr_pid;
        int pcr_packet_count;
        int pcr_packet_period;
    };

    struct TSWrite {
        TSSection pat;
        TSSection sdt;
        TSService **services;
        int sdt_packet_count; 
        int sdt_packet_period;
        int pat_packet_count;            
        int pat_packet_period;
        int nb_services;
        int onid;
        int tsid;
        int64_t first_pcr;
        int mux_rate;
        int pes_payload_size;

        int transport_stream_id;
        int original_network_id;
        int service_id;

        int pmt_start_pid;
        int start_pid;
        int m2ts_mode;

        int reemit_pat_pmt;

        int pcr_period;
        int flags;
        int copyts;
        int tables_version;
        
        int omit_video_pes_length;

        AVRational itime_base;
    };

    struct TSWriteStream {
        struct TSService *service;
        int pid; // Stream associated pid
        int cc;
        int payload_size;
        int first_pts_check; // First pts check needed
        int prev_payload_key;
        int64_t payload_pts;
        int64_t payload_dts;
        int payload_flags;
        uint8_t *payload;
        FormatContext *amux;
        AVRational user_tb;
    };

private:
    int init(AVRational itime_base);

    int ts_init(FormatContext *&ic, xfile::File *f);
    void ts_free(FormatContext *&ic);

private:
    static int ts_write_packet(FormatContext *s, Packet *pkt);
    static TSService *ts_add_service(TSWrite *ts, int sid,
            const char *provider_name, const char *service_name);
    static void section_write_packet(TSSection *s, const uint8_t *packet);
    static int ts_write_packet_internal(FormatContext *s, Packet *pkt);
    static void ts_write_pes(FormatContext *s, Stream *st,
            const uint8_t *payload, int payload_size,
            int64_t pts, int64_t dts, int key);
    static void retransmit_si_info(FormatContext *s, int force_pat);
    static void ts_write_sdt(FormatContext *s);
    static void ts_write_pat(FormatContext *s);
    static int ts_write_pmt(FormatContext *s, TSService *service);
    static int ts_write_section1(TSSection *s, int tid, int id,
            int version, int sec_num, int last_sec_num,
            uint8_t *buf, int len);
    static void ts_write_section(TSSection *s, uint8_t *buf, int len);
    static void ts_insert_pcr_only(FormatContext *s, Stream *st);
    static int64_t get_pcr(const TSWrite *ts, xfile::File *f);
    static int write_pcr_bits(uint8_t *buf, int64_t pcr);
    static void ts_prefix_m2ts_header(FormatContext *s);
    static void ts_insert_null_packet(FormatContext *s);
    static void set_af_flag(uint8_t *pkt, int flag);
    static uint8_t *get_ts_payload_start(uint8_t *pkt);
    static void extend_af(uint8_t *pkt, int size);
    static void write_pts(uint8_t *q, int fourbits, int64_t pts);
    static void ts_write_flush(FormatContext *s);

private:
    static OutputFormat ts_muxer;

private:
    FormatContext *m_ic;
    xfile::File *m_file;
};

}

#endif /* end of _TS_MUXER_H_ */
