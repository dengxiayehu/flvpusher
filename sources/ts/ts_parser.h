#ifndef _TS_PARSER_H_
#define _TS_PARSER_H_

#include <xutil.h>
#include <ffmpeg.h>

#include "ts_comm.h"

using namespace ffmpeg;

namespace flvpusher {

class TSPusher;

class TSParser {
public:
    TSParser();
    ~TSParser();

    int set_file(const std::string &mp4_file, bool hls_segment);

    int get_resolution(uint32_t &width, uint32_t &height);

    bool eof() const;

    int process(void *opaque, FrameCb cb);

    void ask2quit();

    int64_t get_start_time() const;

private:
    struct TSFilter;

    struct Program {
        unsigned int id; // program id/service id
        unsigned int nb_pids;
        unsigned int pids[MAX_PIDS_PER_PROGRAM];
        // Have we found pmt for this program
        int pmt_found;
        unsigned int running_status;
    };

    struct TSContext {
        int raw_packet_size;
        int stop_parse;
        off_t last_pos;
        int current_pid;
        TSFilter *pids[NB_PID_MAX];
        int8_t crc_validity[NB_PID_MAX];
        unsigned int nb_prg;
        struct Program *prg;
        Packet *pkt;
        FormatContext *stream;
    };

    enum TSFilterType {
        TS_PES,
        TS_SECTION,
        TS_PCR,
    };

    typedef int PESCallback(TSFilter *f, const uint8_t *buf, int len,
            int is_start, off_t pos);
    struct TSPESFilter {
        PESCallback *pes_cb;
        void *opaque;
    };

    typedef void SectionCallback(TSFilter *f, const uint8_t *buf, int len);
    struct TSSectionFilter {
        int section_index;
        int section_h_size;
        uint8_t *section_buf;
        unsigned int check_crc : 1;
        unsigned int end_of_section_reached : 1;
        SectionCallback *section_cb;
        void *opaque;
    };

    struct TSFilter {
        int pid;
        int last_cc; // Last cc code (-1 if first packet)
        int64_t last_pcr;
        enum TSFilterType type;
        union {
            TSPESFilter pes_filter;
            TSSectionFilter section_filter;
        } u;
    };

    struct SectionHeader { 
        uint8_t tid;
        uint16_t id;
        uint8_t version;
        uint8_t sec_num;
        uint8_t last_sec_num;
    };

    // TS stream handling
    enum TSState {
        TS_HEADER = 0,
        TS_PESHEADER,
        TS_PESHEADER_FILL,
        TS_PAYLOAD,
        TS_SKIP,
    };

    struct PESContext {
        int pid;
        int pcr_pid; // If -1 then all packets containing PCR are considered
        int stream_type;
        FormatContext *stream;
        Stream *st;
        TSContext *ts;
        enum TSState state;
        // Used to get the format
        uint8_t *data;
        int data_index;
        int total_size;
        int pes_header_size;
        uint8_t header[MAX_PES_HEADER_SIZE];
        int64_t pts, dts;
        int64_t ts_packet_pos; // Position of first TS packet of this PES packet
    };

    struct StreamType {
        uint32_t stream_type;
        enum MediaType codec_type;
        enum CodecID codec_id;
    };

private:
    static int get_packet_size(const uint8_t *buf, int size);
    static int analyze(const uint8_t *buf, int size,
            int packet_size, int *index);

    static void pat_cb(TSFilter *filter,
            const uint8_t *section, int section_len);
    static void pmt_cb(TSFilter *filter,
            const uint8_t *section, int section_len);
    static void sdt_cb(TSFilter *filter,
            const uint8_t *section, int section_len);

    static TSFilter *ts_open_filter(TSContext *ts, unsigned int pid,
            TSFilterType type);
    static TSFilter *ts_open_section_filter(TSContext *ts, unsigned int pid,
            SectionCallback *section_cb,
            void *opaque,
            int check_crc);
    static TSFilter *ts_open_pes_filter(TSContext *ts, unsigned int pid,
            PESCallback *pes_cb,
            void *opaque);
    static TSFilter *ts_open_pcr_filter(TSContext *ts, unsigned int pid);

    static int handle_packets(TSContext *ts, int64_t nb_packets);
    static int handle_packet(TSContext *ts, const uint8_t *packet);
    static int ts_read_packet(FormatContext *s, Packet *pkt);

    static int read_packet(TSContext *ts, uint8_t *buf);
    static void finished_reading_packet(TSContext *ts);

    static int parse_pcr(int64_t *ppcr_high, int *ppcr_low,
            const uint8_t *packet);

    static void write_section_data(TSContext *ts, TSFilter *tssl,
            const uint8_t *buf, int buf_size, int is_start);

    static int ts_init(TSContext *&ts, xfile::File *file);
    static void ts_free(TSContext *&ts);
    static void ts_close_filter(TSContext *ts, TSFilter *filter);

    static int parse_section_header(SectionHeader *h,
            const uint8_t **pp, const uint8_t *p_end);

    static void clear_programs(TSContext *ts);
    static void clear_program(TSContext *ts, unsigned int programid);

    static void add_pat_entry(TSContext *ts, unsigned int programid);
    static Program *get_program(TSContext *ts, unsigned int programid);
    static void add_pid_to_pmt(TSContext *ts, unsigned int programid,
            unsigned int pid);
    static void set_pmt_found(TSContext *ts, unsigned int programid);

    static PESContext *add_pes_stream(TSContext *ts, int pid, int pcr_pid);

    static int ts_push_data(TSFilter *filter,
            const uint8_t *buf, int buf_size, int is_start,
            off_t pos);

    static void new_pes_packet(PESContext *pes, Packet *pkt);
    static void reset_pes_packet_state(PESContext *pes);

    static int64_t parse_pes_pts(const uint8_t *buf);

    static Program *new_program(TSContext *ts, unsigned int programid,
            unsigned int running_status);

    static int ts_set_stream_info(Stream *st, PESContext *pes,
            uint32_t stream_type);

    static void ts_find_stream_type(Stream *st,
            uint32_t stream_type, const StreamType *types);

    int init();

private:
    static InputFormat mpegts_demuxer;

private:
    xfile::File m_file;

    TSContext *m_ts;
};

}

#endif /* end of _TS_PARSER_H_ */
