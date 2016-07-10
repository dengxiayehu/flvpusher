#ifndef _RTSP_COMMON_H_
#define _RTSP_COMMON_H_

#include <string>
#include <vector>

#include <xnet.h>
#include <xmedia.h>
#include <ffmpeg.h>
#include <xfile.h>
#include <xqueue.h>

#include "rtp_receiver.h"

#define RTSP_PROTOCOL_PORT  554
#define CRLF    "\r\n"
#define RTSP_MSG_BUFSIZ     20000

using namespace xnet;
using namespace ffmpeg;

namespace flvpusher {

enum ServerState {
    StateInit = 0,
    StateConnected,
    StateReady,
    StatePlaying,
    StatePause,
};

enum TransportMode {
    RtpUdp = 1,
    RtpTcp,
    RawUdp
};

struct RtspUrl {
    AddressPort srvap;
    std::string username;
    std::string passwd;
    std::string stream_name;

    std::string to_string() const;
};

struct RtspRecvBuf {
    uint8_t buf[RTSP_MSG_BUFSIZ];
    int nread;
    uint8_t *last_crlf;

    RtspRecvBuf();
    int get_max_bufsz() const;
    void reset();
};

class Rtsp : public Tcp {
public:
    Rtsp();
    virtual ~Rtsp();

    void add_field(const std::string &field);
    std::string field2string() const;

protected:
    static int parse_url(const std::string surl, RtspUrl &rtsp_url);

protected:
    ServerState m_stat;
    int m_cseq;
    std::string m_session;
    std::vector<std::string> m_fields;
};

#define EVENT_REPORT    1
#define EVENT_SDES      2

typedef void TaskFunc(void *client_data);
typedef void *TaskToken;

class MediaSubsession;
class MultiFramedRTPSink;
class MultiFramedRTPSource;

class Rtcp {
public:
    Rtcp(Udp *udp, const char *cname, MediaSubsession *subsess);
    Rtcp(Udp *udp, MultiFramedRTPSink *sink, MultiFramedRTPSource *source);
    virtual ~Rtcp();

    void set_stream_socket(int sockfd, int stream_channel_id);

#pragma pack(1)
    struct RtcpCommon {
        unsigned count:5;
        unsigned p:1;
        unsigned version:2;
        unsigned pt:8;
        unsigned length:16;
        uint32_t ssrc;
    };
#pragma pack()

    struct StrType {
        char *ptr;
        ssize_t slen;
    };

    struct RtcpSDES {
        StrType cname;
        StrType name;
        StrType email;
        StrType phone;
        StrType loc;
        StrType tool;
        StrType note;
    };

    struct RtcpSR {
        uint32_t ntp_sec;
        uint32_t ntp_frac;
        uint32_t rtp_ts;
        uint32_t sender_pcount;
        uint32_t sender_bcount;
    };

#pragma pack(1)
    struct RtcpRR {
        uint32_t ssrc;
        uint32_t fract_lost:8;
        uint32_t total_lost_2:8;
        uint32_t total_lost_1:8;
        uint32_t total_lost_0:8;
        uint32_t last_seq;
        uint32_t jitter;
        uint32_t lsr;
        uint32_t dlsr;
    };
#pragma pack()

    struct RtcpSRPkt {
        RtcpCommon common;
        RtcpSR sr;
        RtcpRR rr;
    };

    struct RtcpRRPkt {
        RtcpCommon common;
        RtcpRR rr;
    };

private:
    static void network_read_handler(Rtcp *source, int mask);
    void network_read_handler1(int mask);

    void parse_rtcp_SDES(const uint8_t *pkt, size_t size);
    void parse_rtcp_BYE(const uint8_t *pkt, size_t size);
    void parse_rtcp_SR_RR(const uint8_t *pkt, size_t size);

    static void on_expire(void *client_data);
    void on_expire1();

    void send_sdes();

private:
    Udp *m_udp;
    MediaSubsession *m_subsess;
    RtcpSDES m_peer_sdes;
    enum {RTCP_RX_SDES_BUF_LEN = 64};
    char m_peer_sdes_buf[RTCP_RX_SDES_BUF_LEN];
    int m_type_of_event;
    TaskToken m_on_expire_task;
    MultiFramedRTPSink *m_sink;
    MultiFramedRTPSource *m_source;
};

class MultiFramedRTPSource {
public:
    MultiFramedRTPSource(Udp *udp, unsigned char rtp_payload_format,
                         unsigned rtp_timestamp_frequency, void *opaque = NULL);
    virtual ~MultiFramedRTPSource();

    int start_receiving();

    virtual int set_dump_filename(const std::string &filename)
    { return m_file.open(STR(filename), "wb") ? 0 : -1; }

protected:
    virtual bool process_special_header(uint8_t *payload, unsigned payload_len,
                                        bool marker_bit, unsigned &result_special_header_size) = 0;
    virtual const char *MIME_type() const = 0;
    virtual const unsigned next_enclosed_frame_size(unsigned data_size) { return data_size; }
    virtual const CodecID codec_id() const = 0;
    virtual int on_complete_frame1(FrameBuffer *frame) = 0;

private:
    static void network_read_handler(MultiFramedRTPSource *source, int mask);
    void network_read_handler1(int mask);

    static int on_complete_frame(MultiFramedRTPSource *source, FrameBuffer *frame);

    enum {INITIAL_TIMESTAMP_OFFSET = 1989};

protected:
    Udp *m_udp;
    unsigned char m_rtp_payload_format;
    unsigned m_rtp_timestamp_frequency;
    bool m_are_doing_network_reads;
    Receiver m_receiver;
    uint32_t m_ssrc;
    bool m_current_packet_begins_frame;
    bool m_current_packet_completes_frame;
    bool m_received_pkt;
    uint16_t m_last_received_seq_num;
    uint32_t m_last_received_timestamp;
    xutil::MemHolder m_mem_holder;
    xfile::File m_file;
    uint32_t m_start_complete_timestamp;
    void *m_opaque;
};

class SPropRecord {
public:
    SPropRecord() : m_s_prop_bytes(NULL) { }
    ~SPropRecord() { SAFE_FREE(m_s_prop_bytes); }

    unsigned &s_prop_length() { return m_s_prop_length; }
    unsigned char *&s_prop_bytes() { return m_s_prop_bytes; }

private:
    unsigned m_s_prop_length;
    unsigned char *m_s_prop_bytes;
};

class H264VideoRTPSource : public MultiFramedRTPSource {
public:
    H264VideoRTPSource(Udp *udp, unsigned char rtp_payload_format,
                       unsigned rtp_timestamp_frequency, const char *s_prop_parm_str = NULL,
                       void *opaque = NULL);
    virtual ~H264VideoRTPSource();

protected:
    virtual bool process_special_header(uint8_t *payload, unsigned payload_len,
                                        bool marker_bit, unsigned &result_special_header_size);
    virtual const char *MIME_type() const { return "video/H264"; }
    virtual const CodecID codec_id() const { return CODEC_ID_H264; }
    virtual int on_complete_frame1(FrameBuffer *frame);

private:
    unsigned char m_cur_pkt_NALU_type;
    unsigned char *m_sps;
    unsigned m_sps_size;
    unsigned char *m_pps;
    unsigned m_pps_size;
};

class MPEG4GenericRTPSource : public MultiFramedRTPSource {
public:
    MPEG4GenericRTPSource(Udp *udp,
                          unsigned char rtp_payload_format,
                          unsigned rtp_timestamp_frequency,
                          const char *medium_name,
                          const char *mode,
                          unsigned size_length, unsigned index_length,
                          unsigned index_delta_length,
                          const char *fmtp_config,
                          void *opaque = NULL);
    virtual ~MPEG4GenericRTPSource();

protected:
    virtual bool process_special_header(uint8_t *payload, unsigned payload_len,
                                        bool marker_bit, unsigned &result_special_header_size);
    virtual const char *MIME_type() const { return m_MIME_type; }
    virtual const unsigned next_enclosed_frame_size(unsigned data_size);
    virtual const CodecID codec_id() const { return CODEC_ID_AAC; }
    virtual int on_complete_frame1(FrameBuffer *frame);

private:
    unsigned m_size_length;
    unsigned m_index_length;
    unsigned m_index_delta_length;
    char *m_MIME_type;
    unsigned m_num_au_headers;
    unsigned m_next_au_header;
    struct AUHeader {
        unsigned size;
        unsigned index;
    } *m_au_headers;
    char *m_fmtp_config;
};

#ifndef MILLION
#  define MILLION 1000000
#endif

inline void normalize_timeval(timeval &tv)
{
    if (tv.tv_usec < 0) {
        int nborrow = (-tv.tv_usec)/MILLION + 1;
        tv.tv_usec += nborrow*MILLION;
        tv.tv_sec -= nborrow;
    } else if (tv.tv_usec >= MILLION) {
        int ngiven = tv.tv_usec/MILLION;
        tv.tv_usec %= MILLION;
        tv.tv_sec += ngiven;
    }
}

inline bool operator>=(timeval arg1, timeval arg2)
{
    normalize_timeval(arg1);
    normalize_timeval(arg2);
    if (arg1.tv_sec > arg2.tv_sec)
        return true;
    else if (arg1.tv_sec < arg2.tv_sec)
        return false;
    else 
        return arg1.tv_usec >= arg2.tv_usec;
}

inline bool operator<(timeval arg1, timeval arg2)
{
    return !(arg1 >= arg2);
}

inline bool operator==(timeval arg1, timeval arg2)
{
    normalize_timeval(arg1);
    normalize_timeval(arg2);
    return arg1.tv_sec == arg2.tv_sec && arg1.tv_usec == arg2.tv_usec;
}

inline bool operator!=(timeval arg1, timeval arg2)
{
    return !(arg1 == arg2);
}

inline void operator-=(timeval &arg1, timeval arg2)
{
    arg1.tv_sec -= arg2.tv_sec;
    arg1.tv_usec -= arg2.tv_usec;
    normalize_timeval(arg1);
}

inline void operator+=(timeval &arg1, timeval &arg2)
{
    arg1.tv_sec += arg2.tv_sec;
    arg1.tv_usec += arg2.tv_usec;
    normalize_timeval(arg1);
}

inline timeval operator-(timeval &arg1, timeval &arg2)
{
    timeval tv;
    tv.tv_sec = arg1.tv_sec - arg2.tv_sec;
    tv.tv_usec = arg1.tv_usec - arg2.tv_usec;
    normalize_timeval(tv);
    return tv;
}

inline timeval time_now()
{
    timeval tv;
    gettimeofday(&tv, NULL);
    return tv;
}

class DelayQueue;

class DelayQueueEntry {
public:
    virtual ~DelayQueueEntry();

    intptr_t token() { return m_token; }

protected:
    DelayQueueEntry(timeval tv);

    virtual void handle_timeout();

private:
    friend class DelayQueue;
    DelayQueueEntry *m_next;
    DelayQueueEntry *m_prev;
    timeval m_delta_time_remaining;

    intptr_t m_token;
    static intptr_t token_counter;
};

class AlarmHandler : public DelayQueueEntry {
public:
    AlarmHandler(TaskFunc *proc, void *client_data, timeval tv);

private:
    virtual void handle_timeout() {
        (*m_proc)(m_client_data);
        DelayQueueEntry::handle_timeout();
    }

private:
    TaskFunc *m_proc;
    void *m_client_data;
};

class DelayQueue : public DelayQueueEntry {
public:
    DelayQueue();
    virtual ~DelayQueue();

    void add_entry(DelayQueueEntry *new_entry);
    void remove_entry(DelayQueueEntry *entry);
    DelayQueueEntry *remove_entry(intptr_t token_to_find);
    const timeval time_to_next_alarm();
    void handle_alarm();

private:
    DelayQueueEntry *head() { return m_next; }
    DelayQueueEntry *find_entry_by_token(intptr_t token_to_find);
    void synchronize();

private:
    timeval m_last_sync_time;
};

class HandlerSet;

class TaskScheduler {
public:
    TaskScheduler(unsigned max_scheduler_granularity = 10000/*microseconds*/);
    ~TaskScheduler();

#define SOCKET_READABLE (1<<1)
#define SOCKET_WRITABLE (1<<2)
#define SOCKET_EXCEPTION (1<<3)

    typedef void BackgroundHandlerProc(void *client_data, int mask);

    int do_event_loop(volatile bool *watch_variable);
    void ask2quit() { if (m_watch_variable) *m_watch_variable = true; }

    int single_step(unsigned max_delay_time = 10000);

    void turn_on_background_read_handling(int socket_num,
                                          BackgroundHandlerProc *handler_proc, void *client_data)
    { set_background_handling(socket_num, SOCKET_READABLE, handler_proc, client_data); }
    void turn_off_background_read_handling(int socket_num)
    { disable_background_handling(socket_num); }

    void set_background_handling(int socket_num,
                                 int condition_set, BackgroundHandlerProc *handler_proc, void *client_data);
    void disable_background_handling(int socket_num)
    { set_background_handling(socket_num, 0, NULL, NULL); }

    TaskToken schedule_delayed_task(int64_t microseconds, TaskFunc *proc,
                                    void *client_data);
    void unschedule_delayed_task(TaskToken &prev_task);

private:
    int m_max_scheduler_granularity;
    int m_max_num_sockets;
    fd_set m_read_set;
    fd_set m_write_set;
    fd_set m_exception_set;
    int m_last_handled_socket_num;
    HandlerSet *m_handlers;
    DelayQueue m_delay_queue;
    volatile bool *m_watch_variable;
};

struct HandlerDescriptor {
    int socket_num;
    int condition_set;
    TaskScheduler::BackgroundHandlerProc *handler_proc;
    void *client_data;
};

class HandlerSet {
public:
    HandlerSet();
    virtual ~HandlerSet();

    void assign_handler(int socket_num, int condition_set,
                        TaskScheduler::BackgroundHandlerProc *handler_proc, void *client_data);
    void clear_handler(int socket_num);
    void move_handler(int old_socket_num, int new_socket_num);

    typedef std::vector<HandlerDescriptor *> HDVec;
    typedef HDVec::iterator Iterator;
    Iterator begin() { return m_handlers.begin(); }
    Iterator end() { return m_handlers.end(); }

private:
    HDVec m_handlers;
};

class MediaSession;
class MediaSubsession;

class RtspClient : public Rtsp {
private:
    struct ResponseInfo {
        unsigned response_code;
        char *response_str;
        char *session_parm_str;
        char *transport_parm_str;
        char *scale_parm_str;
        char *range_parm_str;
        char *rtp_info_parm_str;
        char *public_parm_str;
        char *content_base_parm_str;
        char *content_type_parm_str;
        char *body_start;
        unsigned num_body_bytes;

        ResponseInfo();
        ~ResponseInfo();
        void reset();
    };

public:
    RtspClient(void *opaque = NULL);
    virtual ~RtspClient();

    int open(const std::string &url, AddressPort &ap);
    virtual void close();

    int send_request(const char *cmd_url, const std::string &request, const std::string &content = "");
    int recv_response(ResponseInfo *ri);
    int request_options(TaskFunc *proc = NULL);
    int request_describe(std::string &sdp, TaskFunc *proc = NULL);
    int request_setup(const std::string &sdp, bool stream_outgoing = false, bool stream_using_tcp = false);
    int request_play();
    int request_teardown();
    int request_get_parameter(TaskFunc *proc = NULL);
    int request_announce(const std::string &sdp);

    int request_setup(MediaSubsession &subsession,
                      bool stream_outgoing = false,
                      bool stream_using_tcp = false,
                      bool force_multicast_on_unspecified = false);
    int request_play(MediaSession &session,
                     double start = 0.0f, double end = -1.0f, float scale = 1.0f);

    void construct_subsession_url(MediaSubsession const &subsession,
                                  const char *&prefix,
                                  const char *&separator,
                                  const char *&suffix);
    const char *session_url(MediaSession const &session) const;

    void set_user_agent_str(const std::string &user_agent_str)
    { m_user_agent_str = user_agent_str; }

    double &duration() { return m_duration; }

    int loop(volatile bool *watch_variable);

    static void continue_after_option(void *client_data);
    static void continue_after_describe(void *client_data);
    static void continue_after_get_parameter(void *client_data);

private:
    static char *get_line(char *start_of_line);
    static bool parse_response_code(char *line,
                                    unsigned &response_code, char *&response_string);
    static bool check_for_header(char *line,
                                 char const *header_name, unsigned header_name_length,
                                 char *&header_parm);

    int parse_transport_parms(const char *parms_str,
                              char *&server_address_str, PortNumBits &server_port_num);

    char *create_blocksize_string(bool stream_using_tcp);

    std::string generate_cmd_url(const char *base_url,
                                 MediaSession *session = NULL, MediaSubsession *subsession = NULL);

    void schedule_liveness_command();
    static void send_liveness_command(void *client_data);

    static void stream_timer_handler(void *client_data);
    static void shutdown_stream(RtspClient *rtsp_client);

    static bool rtsp_option_is_supported(const char *command_name,
                                         const char *public_parm_str);

private:
    RtspRecvBuf m_rrb;
    std::string m_user_agent_str;
    char *m_base_url;
    uint16_t m_desired_max_incoming_packet_size;
    unsigned m_session_timeout_parameter;
    double m_duration;
    char *m_last_session_id;
    TaskToken m_liveness_command_task;
    TaskToken m_stream_timer_task;
    MediaSession *m_sess;
    bool m_server_supports_get_parameter;
    void *m_opaque;
    int m_tcp_stream_id_count;
};

class SDPAttribute {
public:
    SDPAttribute(char const* str_value, bool value_is_hexadecimal);
    virtual ~SDPAttribute();

    char const* str_value() const { return m_str_value; }
    char const* str_value_to_lower() const { return m_str_value_to_lower; }
    int int_value() const { return m_int_value; }
    bool value_is_hexadecimal() const { return m_value_is_hexadecimal; }

private:
    char *m_str_value;
    char *m_str_value_to_lower;
    int m_int_value;
    bool m_value_is_hexadecimal;
};

class MediaSession {
public:
    MediaSession(void *opaque = NULL);
    ~MediaSession();

    int initialize_with_sdp(const std::string &sdp);
    int parse_sdp_line(const char *input_line, const char *&next_line);
    int parse_sdp_line_s(const char *sdp_line);
    int parse_sdp_line_i(const char *sdp_line);
    int parse_sdp_line_c(const char *sdp_line);
    int parse_sdp_attr_control(const char *sdp_line);
    int parse_sdp_attr_range(const char *sdp_line);
    int parse_sdp_attr_type(const char *sdp_line);
    int parse_sdp_attr_source_filter(const char *sdp_line);

    MediaSubsession *create_new_media_subsession();

    int setup_subsessions(RtspClient *rtsp_client, bool stream_outgoing = false, bool stream_using_tcp = false);
    int play_subsessions(RtspClient *rtsp_client);
    int enable_subsessions_data();

    static MediaSession *create_new(const char *sdp, void *opaque = NULL);
    static char *lookup_payload_format(unsigned char rtp_payload_type,
                                       unsigned &freq, unsigned &nchannel);
    static unsigned guess_rtp_timestamp_frequency(const char *medium_name, const char *codec_name);

    double &play_start_time() { return m_max_play_start_time; }
    double &play_end_time() { return m_max_play_end_time; }
    const char *connection_endpoint_name() const { return m_conn_endpoint_name; };
    const char *control_path() const { return m_control_path; }
    char *abs_start_time() const;
    char *abs_end_time() const;
    float &scale() { return m_scale; }
    const char *CNAME() const { return m_cname; }

    void *&opaque() { return m_opaque; }

private:
    char *m_sess_name;
    char *m_sess_desc;
    char *m_conn_endpoint_name;
    char *m_control_path;
    double m_max_play_start_time;
    double m_max_play_end_time;
    char *m_media_sess_type;
    char *m_source_filter_name;
    std::vector<MediaSubsession *> m_subsessions;
    char *m_abs_start_time;
    char *m_abs_end_time;
    float m_scale;
    char *m_cname;
    void *m_opaque;
};

class MediaSubsession {
    friend class MediaSession;
public:
    MediaSubsession(MediaSession &parent);
    ~MediaSubsession();

    MediaSession &parent_session() { return m_parent; }
    MediaSession const &parent_session() const { return m_parent; }

    const char *control_path() const { return m_control_path; }
    const char *protocol_name() const { return m_protocol_name; }

    char *&_abs_start_time() { return m_abs_start_time; }
    char *&_abs_end_time() { return m_abs_end_time; }

    int parse_sdp_line_c(const char *sdp_line);
    int parse_sdp_line_b(const char *sdp_line);
    int parse_sdp_attr_rtpmap(const char *sdp_line);
    int parse_sdp_attr_rtcpmux(const char *sdp_line);
    int parse_sdp_attr_control(const char *sdp_line);
    int parse_sdp_attr_range(const char *sdp_line);
    int parse_sdp_attr_fmtp(const char *sdp_line);
    int parse_sdp_attr_source_filter(const char *sdp_line);
    int parse_sdp_attr_x_dimensions(const char *sdp_line);
    int parse_sdp_attr_framerate(const char *sdp_line);

    unsigned short client_port_num() const { return m_client_port_num; }
    unsigned char rtp_payload_format() const { return m_rtp_payload_format; }
    bool rtcp_is_muxed() const { return m_multiplex_rtcp_with_rtp; }
    const char *medium_name() const { return m_medium_name; }
    const char *codec_name() const { return m_codec_name; }

    int initiate(const std::string &own_ip);
    NetAddressBits connection_endpoint_address();
    char *&connection_endpoint_name() { return m_conn_endpoint_name; }

    void set_attr(const char *name, const char *value = NULL, bool value_is_hexadecimal = false);
    int attr_val_int(const char *attr_name);
    unsigned attr_val_unsigned(const char *attr_name)
    { return (unsigned) attr_val_int(attr_name); }
    const char *attr_val_str2lower(const char *attr_name);
    const char *attr_val_str(const char *attr_name);

    void set_session_id(const char *session_id);
    const char *session_id() const { return m_session_id; }

    int create_source_object();

    void close();

    unsigned short &client_port_num() { return m_client_port_num; }
    unsigned short &server_port_num() { return m_server_port_num; }

private:
    MediaSession &m_parent;
    unsigned short m_client_port_num;
    unsigned short m_server_port_num;
    char *m_saved_sdp_lines;
    char *m_medium_name;
    char *m_protocol_name;
    unsigned char m_rtp_payload_format;
    char *m_conn_endpoint_name;
    unsigned m_bandwidth;
    char *m_codec_name;
    unsigned m_rtp_timestamp_frequency;
    unsigned m_num_channels;
    bool m_multiplex_rtcp_with_rtp;
    char *m_control_path;
    double m_play_start_time;
    double m_play_end_time;
    char *m_abs_start_time;
    char *m_abs_end_time;
    typedef std::map<std::string, SDPAttribute *> AttrTable;
    AttrTable m_attr_table;
    char *m_source_filter_name;
    unsigned short m_video_width;
    unsigned short m_video_height;
    unsigned m_video_fps;
    Udp *m_rtp_socket;
    Udp *m_rtcp_socket;
    MultiFramedRTPSource *m_rtp_source;
    Rtcp *m_rtcp;
    char *m_session_id;
};

SPropRecord *parse_s_prop_parm_str(const char *parm_str, unsigned &num_s_prop_records);

class OutPacketBuffer {
public:
    OutPacketBuffer(unsigned preferred_packet_size, unsigned max_packet_size,
                    unsigned max_buffer_size = 0);
    ~OutPacketBuffer();

    static unsigned max_size;
    static void increase_max_size_to(unsigned new_max_size)
    { if (new_max_size > OutPacketBuffer::max_size) OutPacketBuffer::max_size = new_max_size; }

    unsigned char *cur_ptr() const { return &m_buf[m_packet_start + m_cur_offset]; }
    unsigned total_bytes_available() const { return m_limit - (m_packet_start + m_cur_offset); }
    unsigned total_buffer_size() const { return m_limit; }
    unsigned char *packet() const { return &m_buf[m_packet_start]; }
    unsigned cur_packet_size() const { return m_cur_offset; }

    void increment(unsigned num_bytes) { m_cur_offset += num_bytes; }

    void enqueue(unsigned char const *from, unsigned num_bytes);
    void enqueue_word(uint32_t word);
    void insert(unsigned char const *from, unsigned num_bytes, unsigned to_position);
    void insert_word(uint32_t word, unsigned to_position);
    void extract(unsigned char *to, unsigned num_bytes, unsigned from_position);
    uint32_t extract_word(unsigned from_position);

    void skip_bytes(unsigned num_bytes);

    bool is_preferred_size() const { return m_cur_offset >= m_preferred; }
    bool would_overflow(unsigned num_bytes) const {  return m_cur_offset + num_bytes > m_max; }
    unsigned num_overflow_bytes(unsigned num_bytes) const { return m_cur_offset + num_bytes - m_max; }
    bool is_too_big_for_a_packet(unsigned num_bytes) const { return num_bytes > m_max; }

    void set_overflow_data(unsigned overflow_data_offset, unsigned overflow_data_size,
                           struct timeval const &presentation_time,
                           unsigned duration_in_microseconds);
    unsigned overflow_data_size() const { return m_overflow_data_size; }
    struct timeval overflow_presentation_time() const { return m_overflow_presentation_time; }
    unsigned overflow_duration_in_microseconds() const { return m_overflow_duration_in_microseconds; }
    bool have_overflow_data() const { return m_overflow_data_size > 0; }
    void use_overflow_data();

    void adjust_packet_start(unsigned num_bytes);
    void reset_packet_start();
    void reset_offset() { m_cur_offset = 0; }
    void reset_overflow_data()
    { m_overflow_data_offset = m_overflow_data_size = 0; }

private:
    unsigned m_packet_start, m_cur_offset, m_preferred, m_max, m_limit;
    unsigned char *m_buf;

    unsigned m_overflow_data_offset, m_overflow_data_size;
    struct timeval m_overflow_presentation_time;
    unsigned m_overflow_duration_in_microseconds;
};

uint32_t random32();

class MultiFramedRTPSink {
public:
    MultiFramedRTPSink(Udp *udp, uint8_t rtp_payload_type, uint32_t rtp_timestamp_frequency,
                       const char *rtp_payload_format_name, unsigned num_channels = 1);
    virtual ~MultiFramedRTPSink();

    typedef void (after_playing_func) (void *client_data);
    bool start_playing(xutil::Queue<xmedia::Frame *> &queue_src, after_playing_func *after_func,
                       void *after_client_data);
    virtual void stop_playing();
    xutil::Queue<xmedia::Frame *> *queue_source() const { return m_queue_src; }

    uint8_t rtp_payload_type() const { return m_rtp_payload_type; }
    unsigned rtp_timestamp_frequency() const { return m_rtp_timestamp_frequency; }
    void set_rtp_timestamp_frequency(unsigned freq)
    { m_rtp_timestamp_frequency = freq; }
    const char *rtp_payload_format_name() const { return m_rtp_payload_format_name; }

    unsigned num_channels() const { return m_num_channels; }

    virtual char const *sdp_media_type() const = 0;
    virtual char *rtpmap_line() const;
    virtual char const *aux_sdp_line();

    uint16_t current_seq_num() const { return m_seq_num; }
    uint32_t preset_next_timestamp();

    struct timeval const &creation_time() const { return m_creation_time; }

    void set_packet_size(unsigned preferred_packet_size, unsigned max_packet_size);

    typedef void (on_send_error_func)(void* client_data);
    void set_on_send_error_func(on_send_error_func* on_send_error_func, void* on_send_error_func_data) {
        m_on_send_error_func = on_send_error_func;
        m_on_send_error_data = on_send_error_func_data;
    }

    void set_stream_socket(int sockfd, int stream_channel_id);

protected:
    virtual bool continue_playing();

    static void on_source_closure(void *client_data);
    void on_source_closure();

    xutil::Queue<xmedia::Frame *> *m_queue_src;

    uint32_t ssrc() const { return m_ssrc; }
    uint32_t convert_to_rtp_timestamp(struct timeval tv);

    virtual void do_special_frame_handling(unsigned fragmentation_offset,
                                           unsigned char *frame_start,
                                           unsigned num_bytes_in_frame,
                                           struct timeval frame_presentation_time,
                                           unsigned num_remaining_bytes);
    virtual bool allow_fragmentation_after_start() const;
    virtual bool allow_other_frames_after_last_fragment() const;
    virtual bool frame_can_appear_after_packet_start(unsigned char const *frame_start,
                                                     unsigned num_bytes_in_frame) const;
    virtual unsigned special_header_size() const;
    virtual unsigned frame_special_header_size() const;
    virtual unsigned compute_overflow_for_new_frame(unsigned new_frame_size) const;

    bool is_first_packet() const { return m_is_first_packet; }
    bool is_first_frame_in_packet() const { return m_num_frames_used_so_far == 0; }
    unsigned cur_fragmentation_offset() const { return m_cur_fragmentation_offset; }
    void set_marker_bit();
    void set_timestamp(struct timeval frame_presentation_time);
    void set_special_header_word(unsigned word, unsigned word_position = 0);
    void set_special_header_bytes(unsigned char const *bytes, unsigned num_bytes,
                                  unsigned byte_position = 0);
    void set_frame_specific_header_word(unsigned word, unsigned word_position = 0);
    void set_frame_specific_header_bytes(unsigned char const *bytes, unsigned num_bytes,
                                         unsigned byte_position = 0);
    void set_frame_padding(unsigned num_padding_bytes);
    unsigned num_frames_used_so_far() const { return m_num_frames_used_so_far; }
    unsigned our_max_packet_size() const { return m_our_max_packet_size; }

private:
    void build_and_send_packet(bool is_first_packet);
    void pack_frame();
    void send_packet_if_necessary();
    static void send_next(void *first_arg);
    friend void send_next(void *);

protected:
    Udp *m_udp;
    uint8_t m_rtp_payload_type;
    uint64_t m_current_timestamp;
    uint16_t m_seq_num;

private:
    DISALLOW_COPY_AND_ASSIGN(MultiFramedRTPSink);

    after_playing_func *m_after_func;
    void *m_after_client_data;

    uint32_t m_ssrc, m_timestamp_base;
    uint32_t m_rtp_timestamp_frequency;
    bool m_next_timestamp_has_been_preset;
    const char *m_rtp_payload_format_name;
    unsigned m_num_channels;
    struct timeval m_creation_time;

    OutPacketBuffer *m_out_buf;

    bool m_no_frames_left;
    unsigned m_num_frames_used_so_far;
    unsigned m_cur_fragmentation_offset;
    bool m_previous_frame_ended_fragmentation;

    bool m_is_first_packet;
    struct timeval m_next_send_time;
    unsigned m_timestamp_position;
    unsigned m_special_header_position;
    unsigned m_special_header_size;
    unsigned m_cur_frame_specific_header_position;
    unsigned m_cur_frame_specific_header_size;
    unsigned m_total_frame_specific_header_sizes;
    unsigned m_our_max_packet_size;

    on_send_error_func* m_on_send_error_func;
    void* m_on_send_error_data;
};

class H264Fragmenter {
public:
    H264Fragmenter(unsigned input_buffer_max, unsigned max_output_packet_size);
    ~H264Fragmenter();

    bool last_fragment_completed_nal_unit() const { return m_last_fragment_completed_nal_unit; }

private:
    DISALLOW_COPY_AND_ASSIGN(H264Fragmenter);
    unsigned m_input_buffer_size;
    unsigned m_max_output_packet_size;
    unsigned char *m_input_buffer;
    unsigned m_num_valid_data_bytes;
    unsigned m_cur_data_offset;
    bool m_last_fragment_completed_nal_unit;
};

class H264VideoRTPSink : public MultiFramedRTPSink {
public:
    H264VideoRTPSink(Udp *udp, unsigned char rtp_payload_format,
                     uint8_t const *sps = NULL, unsigned sps_size = 0,
                     uint8_t const *pps = NULL, unsigned pps_size = 0);
    virtual ~H264VideoRTPSink();

    virtual char const *sdp_media_type() const;
    virtual char const *aux_sdp_line();

private:
    virtual bool continue_playing();
    virtual void do_special_frame_handling(unsigned fragmentation_offset,
                                           unsigned char *frame_start,
                                           unsigned num_bytes_in_frame,
                                           struct timeval frame_presentation_time,
                                           unsigned num_remaining_bytes);
    virtual bool frame_can_appear_after_packet_start(unsigned char const *frame_start,
                                                     unsigned num_bytes_in_frame) const;

private:
    DISALLOW_COPY_AND_ASSIGN(H264VideoRTPSink);
    H264Fragmenter *m_our_fragmenter;
    char *m_fmtp_sdp_line;
    uint8_t *m_sps; unsigned m_sps_size;
    uint8_t *m_pps; unsigned m_pps_size;
};

class MPEG4GenericRTPSink : public MultiFramedRTPSink {
public:
    MPEG4GenericRTPSink(Udp *udp, unsigned char rtp_payload_format,
                        uint32_t rtp_timestamp_frequency,
                        char const *sdp_media_type_string,
                        char const *mpeg4_mode, char const *config_string,
                        unsigned num_channels);
    virtual ~MPEG4GenericRTPSink();

    virtual char const *sdp_media_type() const;
    virtual char const *aux_sdp_line();

private:
    char const *m_sdp_media_type_string;
    char const *m_mpeg4_mode;
    char const *m_config_string;
    char *m_fmtp_sdp_line;
};

}

#endif /* end of _RTSP_COMMON_H_ */
