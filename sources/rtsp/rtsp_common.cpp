#include <memory>
#include <xlog.h>
#include <get_bits.h>
#include <xmedia.h>
#include <amf.h>

#include "rtsp_common.h"
#include "common/media_pusher.h"

//#define XDEBUG
//#define XDEBUG_RTSP_MESSAGE

#define DEFAULT_USER_AGENT  "flvpusher (dengxiayehu@yeah.net)"

using namespace std;
using namespace xmedia;
using namespace xutil;
using namespace amf;

namespace flvpusher {

static unsigned const rtp_header_size = 12;

static std::map<int, SocketDescriptor *> g_socket_table;

std::string RtspUrl::to_string() const
{
    return sprintf_("rtsp://%s%s/%s",
                    username.empty() ? "" : STR(username + ":" + passwd + "@"),
                    STR(srvap.to_string()),
                    STR(stream_name));
}

RtspRecvBuf::RtspRecvBuf()
{
    reset();
}

int RtspRecvBuf::get_max_bufsz() const
{
    return sizeof(buf);
}

void RtspRecvBuf::reset()
{
    nread = 0;
    last_crlf = &buf[-3];
}

Rtsp::Rtsp() :
    m_stat(StateInit),
    m_cseq(0)
{
}

Rtsp::~Rtsp()
{
}

int Rtsp::parse_url(const string surl, RtspUrl &rtsp_url)
{
    const char *url = STR(surl), *p = strstr(url, "://");
    if (!p) {
        LOGE("RTSP url: No :// in url");
        return -1;
    }

    if (p-url!=4 || strncasecmp(url, "rtsp", 4)) {
        LOGE("Unknown protocol, not rtsp");
        return -1;
    }

    char tmp[2048];
    const char *from = p + 3;
    const char *colon_passwd_start = NULL;
    for (p = from; *p && *p != '/'; ++p) {
        if (*p == ':' && !colon_passwd_start)
            colon_passwd_start = p;
        else if (*p == '@') {
            if (!colon_passwd_start)
                colon_passwd_start = p;

            const char *username_start = from;
            int username_len = colon_passwd_start - username_start;
            strncpy(tmp, username_start, username_len);
            tmp[username_len] = '\0';
            rtsp_url.username = tmp;

            const char *passwd_start = colon_passwd_start;
            if (passwd_start < p) ++passwd_start;
            int passwd_len = p - passwd_start;
            strncpy(tmp, passwd_start, passwd_len);
            tmp[passwd_len] = '\0';
            rtsp_url.passwd = tmp;

            from = p + 1;
            break;
        }
    }

    int i;
    for (i = 0;
         from[i] && from[i] != ':' && from[i] != '/';
         ++i)
        tmp[i] = from[i];
    tmp[i] = '\0';
    rtsp_url.srvap.set_address(tmp);

    if (from[i] == ':') {
        for (p = from + i + 1, i = 0;
             *p && *p != '/';
             ++i, ++p)
            tmp[i] = *p;
        tmp[i] = '\0';
        rtsp_url.srvap.set_port(atoi(tmp));
        from = p;
    } else {
        rtsp_url.srvap.set_port(RTSP_PROTOCOL_PORT);
        from += i;
    }

    rtsp_url.stream_name = ++from;
    return 0;
}

void Rtsp::add_field(const std::string &field)
{
    if (field.empty()) return;
    m_fields.push_back(field+CRLF);
}

std::string Rtsp::field2string() const
{
    string str;
    FOR_VECTOR_CONST_ITERATOR(string, m_fields, it) {
        str += (*it);
    }
    return str;
}

static void deregister_socket(int sock_num, unsigned char stream_channel_id)
{
    if (g_socket_table.find(sock_num) != g_socket_table.end()) {
        g_socket_table[sock_num]->deregister_interface(stream_channel_id);
    }
}

Rtcp::Rtcp(TaskScheduler *scheduler, RtpInterface *interface, const char *cname, MediaSubsession *subsess) :
    m_interface(interface), m_subsess(subsess), m_type_of_event(EVENT_SDES),
    m_on_expire_task(NULL),
    m_scheduler(scheduler)
{
    m_scheduler->turn_on_background_read_handling(m_interface->get_sockfd(),
            (TaskScheduler::BackgroundHandlerProc *) &Rtcp::network_read_handler, this);

    on_expire1();
}

Rtcp::~Rtcp()
{
    m_scheduler->unschedule_delayed_task(m_on_expire_task);
}

void Rtcp::set_stream_socket(int sockfd, unsigned char stream_channel_id)
{
    m_interface->set_stream_socket(sockfd, stream_channel_id);
}

void Rtcp::network_read_handler(Rtcp *source, int mask)
{
    source->network_read_handler1(mask);
}

static const unsigned MaxRTCPPacketSize = 1456;

#define RTCP_PT_MIN  192
/* Supplemental H.261 specific RTCP packet types according to Section C.3.5 */
#define RTCP_FIR     192
#define RTCP_NACK    193
#define RTCP_SMPTETC 194
#define RTCP_IJ      195
/* RTCP packet types according to Section A.11.1 */
/* And http://www.iana.org/assignments/rtp-parameters */
#define RTCP_SR      200
#define RTCP_RR      201
#define RTCP_SDES    202
#define RTCP_BYE     203
#define RTCP_APP     204
#define RTCP_RTPFB   205
#define RTCP_PSFB    206
#define RTCP_XR      207
#define RTCP_AVB     208
#define RTCP_RSI     209
#define RTCP_TOKEN   210

#define RTCP_PT_MAX  210

enum {
    RTCP_SDES_NULL  = 0,
    RTCP_SDES_CNAME = 1,
    RTCP_SDES_NAME  = 2,
    RTCP_SDES_EMAIL = 3,
    RTCP_SDES_PHONE = 4,
    RTCP_SDES_LOC   = 5,
    RTCP_SDES_TOOL  = 6,
    RTCP_SDES_NOTE  = 7
};

void Rtcp::network_read_handler1(int mask)
{
    uint8_t buf[MaxRTCPPacketSize];
    int nread;

    if ((nread = m_interface->read(buf, sizeof(buf))) < 0) {
        LOGE("Read RTCP packet failed");
        return;
    }

    uint8_t *p = buf, *pend = p + nread;
    while (p < pend) {
        RtcpCommon *common = (RtcpCommon *) p;
        unsigned len = (ENTOHS((uint16_t) common->length) + 1)*4;

        switch (common->pt) {
        case RTCP_SR:
        case RTCP_RR:
        case RTCP_XR:
            parse_rtcp_SR_RR(p, len);
            break;

        case RTCP_SDES:
            parse_rtcp_SDES(p, len);
            break;

        case RTCP_BYE:
            parse_rtcp_BYE(p, len);
            break;

        default:
            break;
        }

        p += len;
    }
}

void Rtcp::parse_rtcp_SR_RR(const uint8_t *pkt, size_t size)
{
    RtcpCommon *common = (RtcpCommon *) pkt;
    const RtcpRR *rr = NULL;
    const RtcpSR *sr = NULL;

    // Parse RTCP
    if (common->pt == RTCP_SR) {
        sr = (RtcpSR *)(pkt + sizeof(RtcpCommon));
        if (common->count > 0 && size >= (sizeof(RtcpSRPkt))) {
            rr = (RtcpRR *)(pkt + sizeof(RtcpCommon) + sizeof(RtcpSR));
        }
#ifdef XDEBUG
        LOGD("SR%s received", rr ? "(contains RR)" : "");
#endif
    } else if (common->pt == RTCP_RR && common->count > 0) {
        rr = (RtcpRR *) (pkt + sizeof(RtcpCommon));
#ifdef XDEBUG
        LOGD("RR received");
#endif
    }

    // Ignore received SR&RR
}

void Rtcp::parse_rtcp_SDES(const uint8_t *pkt, size_t size)
{
    RtcpSDES *sdes = &m_peer_sdes;
    char *p = (char *) pkt + 8, *pend = (char *) pkt + size;

    memset(sdes, 0, sizeof(*sdes));
    char *b = m_peer_sdes_buf, *bend = b + sizeof(m_peer_sdes_buf);

    while (p < pend) {
        uint8_t sdes_type, sdes_len;
        StrType sdes_value = {NULL, 0};

        sdes_type = *p++;

        // Check for end of SDES item list
        if (sdes_type == RTCP_SDES_NULL || p == pend)
            break;

        sdes_len = *p++;

        // Check for corrupted SDES packet
        if (p + sdes_len > pend)
            break;

        // Get SDES item
        if (b + sdes_len < bend) {
            memcpy(b, p, sdes_len);
            sdes_value.ptr = b;
            sdes_value.slen = sdes_len;
            b += sdes_len;
        } else {
            // Insufficient SDES buffer
            LOGW("Unsufficient buffer to save RTCP SDES type %d:%.*s",
                    sdes_type, sdes_len, p);
            p += sdes_len;
            continue;
        }

        switch (sdes_type) {
            case RTCP_SDES_CNAME:
                sdes->cname = sdes_value;
                break;
            case RTCP_SDES_NAME:
                sdes->name = sdes_value;
                break;
            case RTCP_SDES_EMAIL:
                sdes->email = sdes_value;
                break;
            case RTCP_SDES_PHONE:
                sdes->phone = sdes_value;
                break;
            case RTCP_SDES_LOC:
                sdes->loc = sdes_value;
                break;
            case RTCP_SDES_TOOL:
                sdes->tool = sdes_value;
                break;
            case RTCP_SDES_NOTE:
                sdes->note = sdes_value;
                break;
            default:
                LOGW("Received unknown RTCP SDES type %d:%.*s",
                        sdes_type, sdes_value.slen, sdes_value.ptr);
                break;
        }

#ifdef XDEBUG
        LOGD("SDES type %d:%.*s",
                sdes_type, sdes_value.slen, sdes_value.ptr);
#endif

        p += sdes_len;
    }
}

void Rtcp::parse_rtcp_BYE(const uint8_t *pkt, size_t size)
{
    StrType reason = {(char *) "-", 1};

    // Check and get BYE reason
    if (size > 8) {
        reason.slen = MIN(((unsigned) sizeof(m_peer_sdes_buf)), ((unsigned) pkt[8]));
        memcpy(m_peer_sdes_buf, pkt+9, reason.slen);
        reason.ptr = m_peer_sdes_buf;
    }

    LOGD("Received RTCP BYE, reasion: %.*s",
            reason.slen, reason.ptr);

    m_subsess->close();
}

void Rtcp::on_expire(void *client_data)
{
    Rtcp *rtcp = (Rtcp *) client_data;

    if (rtcp->m_type_of_event == EVENT_SDES) {
        rtcp->send_sdes();
    } else {
        LOGE("Don't support to send this type of event(%d)",
                rtcp->m_type_of_event);
        return;
    }

    rtcp->on_expire1();
}

void Rtcp::on_expire1()
{
    enum {RTCP_MAX_INTERVAL = 5};
    unsigned u_seconds_to_delay = (rand()%RTCP_MAX_INTERVAL + 1)*MILLION;
    m_on_expire_task = m_scheduler->schedule_delayed_task(
            u_seconds_to_delay, on_expire, this);
}

void Rtcp::send_sdes()
{
    if (!m_subsess) return;

    memset(m_peer_sdes_buf, 0, sizeof(m_peer_sdes_buf));

    RtcpCommon *common = (RtcpCommon *) m_peer_sdes_buf;
    common->version = 2;    // Version: RFC 1889 Version (2)
    common->p = 0;          // Padding
    common->count = 1;      // Source count
    common->pt = RTCP_SDES; // Source description (202)
    common->ssrc = strtol(m_subsess->session_id(), NULL, 16);

    uint8_t *p = (uint8_t *) (m_peer_sdes_buf + sizeof(RtcpCommon)),
            *psave = p;
    const char *cname = m_subsess->parent_session().CNAME();
    int len = strlen(cname);
    put_byte(p, RTCP_SDES_CNAME);
    put_byte(p, len);
    strncpy((char *) p, cname, len); p += len;
    put_byte(p, RTCP_SDES_NULL);

    common->length = EHTONS((p-psave+4+4+3)/4-1);   // Length

    if (m_interface->write((uint8_t *) m_peer_sdes_buf, (ENTOHS(common->length)+1)*4) < 0) {
        LOGE("Send RTCP SDES to server failed");
        // Fall through
    }
}

MultiFramedRTPSource::MultiFramedRTPSource(
        TaskScheduler *scheduler,
        RtpInterface *interface,
        unsigned char rtp_payload_format,
        unsigned rtp_timestamp_frequency,
        void *opaque) :
    m_scheduler(scheduler),
    m_interface(interface),
    m_rtp_payload_format(rtp_payload_format),
    m_rtp_timestamp_frequency(rtp_timestamp_frequency),
    m_are_doing_network_reads(false),
    m_ssrc(0),
    m_current_packet_begins_frame(true),
    m_current_packet_completes_frame(true),
    m_received_pkt(false),
    m_last_received_seq_num(0),
    m_last_received_timestamp(0),
    m_start_complete_timestamp(0),
    m_opaque(opaque)
{
}

MultiFramedRTPSource::~MultiFramedRTPSource()
{
}

int MultiFramedRTPSource::start_receiving()
{
    if (m_are_doing_network_reads) {
        LOGE("This RTP source is already receiving data now");
        return -1;
    }

    m_are_doing_network_reads = true;
    m_scheduler->turn_on_background_read_handling(m_interface->get_sockfd(),
            (TaskScheduler::BackgroundHandlerProc *) &MultiFramedRTPSource::network_read_handler, this);
    return 0;
}

void MultiFramedRTPSource::network_read_handler(MultiFramedRTPSource *source, int mask)
{
    source->network_read_handler1(mask);
}

void MultiFramedRTPSource::network_read_handler1(int mask)
{
    uint8_t buf[MTU];
    int nread = m_interface->read(buf, sizeof(buf));
    if (nread < 0) {
        LOGE("Failed to receive RTP data");
        return;
    }

    if (nread < (int) sizeof(RTPHeaderRaw)) {
        // Ignore keep-alive packets
        return;
    }

    bool pkt_discarded = false;

    RTPHeaderRaw *hdr;
    RTPHeader header;
    const uint8_t *payload = NULL;
    unsigned payload_len = 0;
    unsigned payload_offset = 0;

    if (parse_rtp_header(buf, nread, &hdr, &payload, &payload_len, &header) < 0) {
        LOGE("Failed to decode RTP header");
        return;
    }

    header.timestamp += INITIAL_TIMESTAMP_OFFSET;

    unsigned special_header_size;
    FrameType ft = kFrameUnknown;
    bool is_first_pkt_in_frame = false;

    bool valid = false;
    if (!m_ssrc) {
        m_ssrc = header.ssrc;
        valid = true;
    } else if (header.ssrc == m_ssrc) {
        if (header.payload_type == m_rtp_payload_format)
            valid = true;
    }
    if (!valid) {
        pkt_discarded = true;
        goto on_return;
    }

    if (!payload_len) {
        pkt_discarded = true;
        goto on_return;
    }

    if (process_special_header((uint8_t *) payload, payload_len,
                header.marker_bit, special_header_size)) {
        payload += special_header_size;
        payload_len -= special_header_size;
    }

    if (((uint16_t) (m_last_received_seq_num + 1) == header.sequence_number &&
         m_last_received_timestamp != header.timestamp) || !m_received_pkt)
        is_first_pkt_in_frame = true;

    switch (codec_id()) {
    case CODEC_ID_H264:
        if (m_current_packet_begins_frame) {
            if (!is_first_pkt_in_frame && (payload[1]&0x80))
                is_first_pkt_in_frame = true;

            int nalu_type = payload[0]&0x1F;
            if (nalu_type == 0x07 || nalu_type == 0x08 ||
                nalu_type == 0x05 || nalu_type == 0x06 ) {
                ft = kFrameKey;
                if (header.marker_bit) {
                    /* Combine the following frames into single one
                     * SPS, timestamp:0, m:1
                     * PPS, timestamp:0, m:1
                     * SEI, timestamp:0, m:1
                     * IDR, timestamp:0, m:0 ... */
                    if (nalu_type == 0x07 ||
                        (nalu_type != 0x07 &&
                         header.timestamp == m_last_received_timestamp))
                        header.marker_bit = false;
                }
            } else
                ft = kFrameDelta;
        }
        break;
    case CODEC_ID_AAC:
        ft = kFrameKey;
        is_first_pkt_in_frame = true;
        break;
    default:
        LOGE("Unknown codec_id(%d)", codec_id());
        goto on_return;
    }

    do {
        unsigned cur_frame_size = next_enclosed_frame_size(payload_len);
        Packet *pkt = new Packet((uint8_t *) (payload + payload_offset), cur_frame_size,
                header.sequence_number, header.timestamp, header.marker_bit,
                ft, m_current_packet_begins_frame, is_first_pkt_in_frame);
        m_receiver.insert_packet(pkt,
                (Receiver::CompleteFrameProc *) &MultiFramedRTPSource::on_complete_frame,
                this);
        payload_offset += cur_frame_size;
        payload_len -= cur_frame_size;
        if (payload_len) {
            LOGE("Multi AU headers in one Audio rtp, not supported yet");
            goto on_return;
        }
    } while (payload_len);

on_return:
    m_received_pkt = true;
    m_last_received_seq_num = header.sequence_number;
    m_last_received_timestamp = header.timestamp;
}

int MultiFramedRTPSource::on_complete_frame(MultiFramedRTPSource *source,
        FrameBuffer *frame)
{
    if (!source->m_start_complete_timestamp)
        source->m_start_complete_timestamp = frame->timestamp();
    return source->on_complete_frame1(frame);
}

SPropRecord *parse_s_prop_parm_str(const char *parm_str, unsigned &num_s_prop_records)
{
    // Make a copy of the input string, so we can replace the commas with '\0's:
    char *in_str = strdup(parm_str);
    if (!in_str) {
        num_s_prop_records = 0;
        return NULL;
    }

    // Count the number of commas (and thus the number of parameter sets):
    num_s_prop_records = 1;
    char *s;
    for (s = in_str; *s != '\0'; ++s) {
        if (*s == ',') {
            ++num_s_prop_records;
            *s = '\0';
        }
    }

    // Allocate and fill in the result array:
    SPropRecord *result_array = new SPropRecord[num_s_prop_records];
    s = in_str;
    for (unsigned i = 0; i < num_s_prop_records; ++i) {
        result_array[i].s_prop_bytes() =
            base64_decode(s, strlen(s), result_array[i].s_prop_length());
        s += strlen(s) + 1;
    }

    SAFE_FREE(in_str);
    return result_array;
}

H264VideoRTPSource::H264VideoRTPSource(
        TaskScheduler *scheduler,
        RtpInterface *interface,
        unsigned char rtp_payload_format,
        unsigned rtp_timestamp_frequency,
        const char *s_prop_parm_str,
        void *opaque) :
    MultiFramedRTPSource(scheduler, interface, rtp_payload_format, rtp_timestamp_frequency, opaque),
    m_sps(NULL), m_sps_size(0), m_pps(NULL), m_pps_size(0)
{
    unsigned num_s_prop_records;
    SPropRecord *s_prop_records =
        parse_s_prop_parm_str(s_prop_parm_str, num_s_prop_records);
    for (unsigned i = 0; i < num_s_prop_records; ++i) {
        if (s_prop_records[i].s_prop_length() == 0) continue;
        uint8_t nalu_type = (s_prop_records[i].s_prop_bytes()[0])&0x1F;
        if (nalu_type == 7) {
            m_sps_size = s_prop_records[i].s_prop_length();
            m_sps = (unsigned char *) malloc(m_sps_size);
            memcpy(m_sps, s_prop_records[i].s_prop_bytes(), m_sps_size);
        } else if (nalu_type == 8) {
            m_pps_size = s_prop_records[i].s_prop_length();
            m_pps = (unsigned char *) malloc(m_pps_size);
            memcpy(m_pps, s_prop_records[i].s_prop_bytes(), m_pps_size);
        }
    }
    SAFE_DELETE_ARRAY(s_prop_records);
}

H264VideoRTPSource::~H264VideoRTPSource()
{
    SAFE_FREE(m_sps);
    SAFE_FREE(m_pps);
}

bool H264VideoRTPSource::process_special_header(uint8_t *payload, unsigned payload_len,
        bool marker_bit, unsigned &result_special_header_size)
{
    unsigned num_bytes_to_skip = 0;

    if (payload_len < 4) return false;
    
    if (STARTCODE4(payload)) {
        payload += 4;
        num_bytes_to_skip += 4;
    } else if (STARTCODE3(payload)) {
        payload += 3;
        num_bytes_to_skip += 3;
    }
    payload_len -= num_bytes_to_skip;

    if (payload_len < 1) return false;
    m_cur_pkt_NALU_type = payload[0]&0x1F;
    switch (m_cur_pkt_NALU_type) {
    case 24:// STAP-A
        num_bytes_to_skip += 1;
        break;
    case 25: case 26: case 27: // STAP-B, MTAP16 or MTAP24
        num_bytes_to_skip += 3;
        break;
    case 28: case 29: { // FU-A or FU-B
        // For these NALUs, the first two bytes are the FU indicator and the FU header.
        // If the start bit is set, we reconstruct the original NAL header into byte 1:
        if (payload_len < 2) return false;
        unsigned char start_bit = payload[1]&0x80;
        unsigned char end_bit = payload[1]&0x40;
        if (start_bit) {
            m_current_packet_begins_frame = true;
            payload[1] = (payload[0]&0xE0)|(payload[1]&0x1F);
            num_bytes_to_skip += 1;
        } else {
            // The start bit is not set, so we skip both the FU indicator and header:
            m_current_packet_begins_frame = false;
            num_bytes_to_skip += 2;
        }
        m_current_packet_completes_frame = (end_bit != 0);
        } break;
    default:
        m_current_packet_begins_frame = m_current_packet_completes_frame = true;
        num_bytes_to_skip += 0;
        break;
    }
    result_special_header_size = num_bytes_to_skip;
    return true;
}

int H264VideoRTPSource::on_complete_frame1(FrameBuffer *frame)
{
    int nwritten = 0;
    size_t bytes_max = frame->size_bytes() + frame->size() * 4;
    uint8_t *buf = (uint8_t *) m_mem_holder.alloc(bytes_max);
    if (frame->frame_type() == kFrameKey && m_sps_size && m_pps_size) {
        bytes_max += (m_sps_size + m_pps_size + 2 * 4);
        buf = (uint8_t *) m_mem_holder.alloc(bytes_max);
        memcpy(buf+nwritten, nalu_startcode, 4); nwritten += 4;
        memcpy(buf+nwritten, m_sps, m_sps_size); nwritten += m_sps_size;
        memcpy(buf+nwritten, nalu_startcode, 4); nwritten += 4;
        memcpy(buf+nwritten, m_pps, m_pps_size); nwritten += m_pps_size;
    }
    for (FrameBuffer::Iterator it = frame->begin();
         it != frame->end();
         ++it) {
        Packet *pkt = frame->packet_at(it);
        if (pkt->current_packet_begins_frame()) {
            memcpy(buf+nwritten, nalu_startcode, 4);
            nwritten += 4;
        }
        memcpy(buf+nwritten, pkt->data_ptr(), pkt->size_bytes());
        nwritten += pkt->size_bytes();
    }

#ifdef XDEBUG
    LOGD("VIDEO frame: %05u~%05u, timestamp=%u, bytes_max=%u, nwritten=%d",
            frame->get_low_seq_num(), frame->get_high_seq_num(),
            frame->timestamp(), bytes_max, nwritten);
#endif

    if (m_opaque) {
        ((MediaPusher *) m_opaque)->on_frame(((frame->timestamp()-m_start_complete_timestamp)/(double)m_rtp_timestamp_frequency)*1000,
                                             buf, nwritten, 1);
    }

    if (m_file.is_opened())
        m_file.write_buffer(buf, nwritten);
    return 0;
}

MPEG4GenericRTPSource::MPEG4GenericRTPSource(
        TaskScheduler *scheduler,
        RtpInterface *interface,
        unsigned char rtp_payload_format,
        unsigned rtp_timestamp_frequency,
        const char *medium_name,
        const char *mode,
        unsigned size_length,
        unsigned index_length,
        unsigned index_delta_length,
        const char *fmtp_config,
        void *opaque) :
    MultiFramedRTPSource(scheduler, interface, rtp_payload_format, rtp_timestamp_frequency, opaque),
    m_size_length(size_length), m_index_length(index_length),
    m_index_delta_length(index_delta_length),
    m_num_au_headers(0), m_next_au_header(0), m_au_headers(NULL)
{
    unsigned mime_type_length =
        strlen(medium_name) + strlen("/MPEG4-GENERIC") + 1;
    m_MIME_type = (char *) malloc(mime_type_length);
    if (m_MIME_type)
        sprintf(m_MIME_type, "%s/MPEG4-GENERIC", medium_name);

    m_fmtp_config = strdup(fmtp_config);
}

MPEG4GenericRTPSource::~MPEG4GenericRTPSource()
{
    SAFE_FREE(m_MIME_type);
    SAFE_DELETE_ARRAY(m_au_headers);
    SAFE_FREE(m_fmtp_config);
}

bool MPEG4GenericRTPSource::process_special_header(uint8_t *payload, unsigned payload_len,
        bool marker_bit, unsigned &result_special_header_size)
{
    m_current_packet_begins_frame = m_current_packet_completes_frame;
    m_current_packet_completes_frame = marker_bit;

    result_special_header_size = 0;
    m_num_au_headers = 0;
    m_next_au_header = 0;
    SAFE_DELETE_ARRAY(m_au_headers);

    if (m_size_length > 0) {
        // The packet begins with a "AU Header Section".  Parse it, to
        // determine the "AU-header"s for each frame present in this packet:
        result_special_header_size += 2;
        if (payload_len < result_special_header_size)
            return false;

        unsigned au_headers_length = (payload[0]<<8)|payload[1];
        unsigned au_headers_length_bytes = (au_headers_length+7)/8;
        if (payload_len < result_special_header_size + au_headers_length_bytes)
            return false;
        result_special_header_size += au_headers_length_bytes;

        // Figure out how many AU-headers are present in the packet:
        int bits_avail = au_headers_length - (m_size_length + m_index_length);
        if (bits_avail >= 0 &&
            (m_size_length + m_index_delta_length) > 0)
            m_num_au_headers = 1 + bits_avail/(m_size_length + m_index_delta_length);
        if (m_num_au_headers > 0) {
            m_au_headers = new AUHeader[m_num_au_headers];
            // Fill in each header:
            GetBitContext gb;
            init_get_bits(&gb, &payload[2], au_headers_length);
            m_au_headers[0].size = get_bits(&gb, m_size_length);
            m_au_headers[0].index = get_bits(&gb, m_index_length);
            for (unsigned i = 1; i < m_num_au_headers; ++i) {
                m_au_headers[i].size = get_bits(&gb, m_size_length);
                m_au_headers[i].index = get_bits(&gb, m_index_delta_length);
            }
        }
    }
    return true;
}

const unsigned MPEG4GenericRTPSource::next_enclosed_frame_size(unsigned data_size)
{
    AUHeader *au_header = m_au_headers;
    if (!au_header) return data_size;
    unsigned num_au_headers = m_num_au_headers;

    if (m_next_au_header >= num_au_headers) {
        LOGE("next_enclosed_frame_size(%u): data error(%p,%u,%u)!",
                data_size, au_header, m_next_au_header, num_au_headers);
        return data_size;
    }

    au_header = &au_header[m_next_au_header++];
    return au_header->size <= data_size ? au_header->size : data_size;
}

static bool get_nibble(const char *&config_str,
        uint8_t &result_nibble)
{
    char c = config_str[0];
    if (c == '\0') return false;

    if (c >= '0' && c <= '9')
        result_nibble = c - '0';
    else if (c >= 'A' && c <= 'F')
        result_nibble = 10 + c - 'A';
    else if (c >= 'a' && c <= 'f')
        result_nibble = 10 + c - 'a';
    else
        return false;

    ++config_str;
    return true;
}

static bool get_byte(const char *&config_str, uint8_t &result_byte)
{
    result_byte = 0;

    uint8_t first_nibble;
    if (!get_nibble(config_str, first_nibble)) return false;
    result_byte = first_nibble<<4;

    uint8_t second_nibble = 0;
    if (!get_nibble(config_str, second_nibble) && config_str[0] != '\0')
        return false;
    result_byte |= second_nibble;

    return true;
}

static uint8_t *parse_general_config_str(const char *config_str,
        unsigned &config_size)
{
    uint8_t *config = NULL;

    do {
        if (!config_str) break;
        config_size = (strlen(config_str)+1)/2;

        config = (uint8_t *) calloc(1, config_size);
        if (!config) break;

        unsigned i;
        for (i = 0; i < config_size; ++i)
            if (!get_byte(config_str, config[i])) break;
        if (i != config_size) break;

        return config;
    } while (0);

    config_size = 0;
    SAFE_FREE(config);
    return NULL;
}

unsigned sampling_freq_from_asc(const char *config_str)
{
    uint8_t *config = NULL;
    unsigned result = 0;

    do {
        unsigned config_size;
        config = parse_general_config_str(config_str, config_size);
        if (!config) break;

        LOGW("config[0]=%x, config[1]=%x", config[0], config[1]);

        if (config_size < 2) break;
        unsigned char sampling_freq_index = ((config[0]&0x07)<<1) | (config[1]>>7);
        if (sampling_freq_index < 15) {
            result = atoi(samplerate_idx_to_str(sampling_freq_index));
            break;
        }

        if (config_size < 5) break;
        result = ((config[1]&0x7F)<<17) | (config[2]<<9) | (config[3]<<1) | (config[4]>>7);
    } while (0);

    SAFE_FREE(config);
    return result;
}

int MPEG4GenericRTPSource::on_complete_frame1(FrameBuffer *frame)
{
    uint8_t *buf = (uint8_t *) m_mem_holder.alloc(
            AAC_ADTS_HEADER_SIZE + frame->size_bytes());
    unsigned config_size;
    uint8_t *asc_buf = parse_general_config_str(m_fmtp_config, config_size);
    if (generate_adts_header(asc_buf, frame->size_bytes(), buf) < 0) {
        LOGE("generate_adts_header failed (0x%02x 0x%02x)",
                asc_buf[0], asc_buf[1]);
        SAFE_FREE(asc_buf);
        return -1;
    }
    unsigned nwritten = AAC_ADTS_HEADER_SIZE;
    for (FrameBuffer::Iterator it = frame->begin();
         it != frame->end();
         ++it) {
        Packet *pkt = frame->packet_at(it);
        memcpy(buf+nwritten, pkt->data_ptr(), pkt->size_bytes());
        nwritten += pkt->size_bytes();
    }

#ifdef XDEBUG
    LOGD("AUDIO frame: %05u~%05u, timestamp=%u, nwritten=%d",
           frame->get_low_seq_num(), frame->get_high_seq_num(),
           frame->timestamp(), nwritten);
#endif

    if (m_opaque) {
        ((MediaPusher *) m_opaque)->on_frame(((frame->timestamp()-m_start_complete_timestamp)/(double)m_rtp_timestamp_frequency)*1000,
                                             buf, nwritten, 0);
    }

    if (m_file.is_opened())
        m_file.write_buffer(buf, nwritten);
    SAFE_FREE(asc_buf);
    return 0;
}

RtspClient::ResponseInfo::ResponseInfo() :
    response_code(200), response_str(NULL),
    session_parm_str(NULL),
    transport_parm_str(NULL),
    scale_parm_str(NULL),
    range_parm_str(NULL),
    rtp_info_parm_str(NULL),
    public_parm_str(NULL),
    content_base_parm_str(NULL),
    content_type_parm_str(NULL),
    body_start(NULL), num_body_bytes(0)
{
}

RtspClient::ResponseInfo::~ResponseInfo()
{
    reset();
}

void RtspClient::ResponseInfo::reset()
{
    response_code = 200;
    SAFE_FREE(response_str);
    SAFE_FREE(session_parm_str);
    SAFE_FREE(transport_parm_str);
    SAFE_FREE(scale_parm_str);
    SAFE_FREE(range_parm_str);
    SAFE_FREE(rtp_info_parm_str);
    SAFE_FREE(public_parm_str);
    SAFE_FREE(content_base_parm_str);
    SAFE_FREE(content_type_parm_str);
    SAFE_FREE(body_start);
    num_body_bytes = 0;
}

intptr_t DelayQueueEntry::token_counter = 0;

DelayQueueEntry::DelayQueueEntry(timeval tv) :
    m_delta_time_remaining(tv)
{
    m_next = m_prev = this;
    m_token = ++token_counter;
}

DelayQueueEntry::~DelayQueueEntry()
{
}

void DelayQueueEntry::handle_timeout()
{
    delete this;
}

AlarmHandler::AlarmHandler(TaskFunc *proc, void *client_data, timeval tv) :
    DelayQueueEntry(tv), m_proc(proc), m_client_data(client_data)
{
}

#ifndef INT_MAX
#  define INT_MAX 0x7FFFFFFF
#endif

#define DELAY_ZERO (timeval) {0, 0}

DelayQueue::DelayQueue() :
    DelayQueueEntry((timeval){INT_MAX, MILLION-1}),
    m_last_sync_time(DELAY_ZERO)
{
}

DelayQueue::~DelayQueue()
{
}

void DelayQueue::add_entry(DelayQueueEntry *new_entry)
{
    synchronize();

    DelayQueueEntry *cur = head();
    while (new_entry->m_delta_time_remaining >= cur->m_delta_time_remaining) {
        new_entry->m_delta_time_remaining -=
            cur->m_delta_time_remaining;
        cur = cur->m_next;
    }

    cur->m_delta_time_remaining -=
        new_entry->m_delta_time_remaining;

    new_entry->m_next = cur;
    new_entry->m_prev = cur->m_prev;
    cur->m_prev = new_entry->m_prev->m_next = new_entry;
}

void DelayQueue::synchronize()
{
    timeval now = time_now();
    if (now < m_last_sync_time) {
        m_last_sync_time = now;
        return;
    }
    timeval time_since_last_sync = now - m_last_sync_time;
    m_last_sync_time = now;

    DelayQueueEntry *cur_entry = head();
    while (time_since_last_sync >= cur_entry->m_delta_time_remaining) {
        time_since_last_sync -= cur_entry->m_delta_time_remaining;
        cur_entry->m_delta_time_remaining = DELAY_ZERO;
        cur_entry = cur_entry->m_next;
    }
    cur_entry->m_delta_time_remaining -= time_since_last_sync;
}

void DelayQueue::remove_entry(DelayQueueEntry *entry)
{
    if (entry == NULL || entry->m_next == NULL) return;

    entry->m_next->m_delta_time_remaining += entry->m_delta_time_remaining;
    entry->m_prev->m_next = entry->m_next;
    entry->m_next->m_prev = entry->m_prev;
    entry->m_next = entry->m_prev = NULL;
}

DelayQueueEntry *DelayQueue::remove_entry(intptr_t token_to_find)
{
    DelayQueueEntry* entry = find_entry_by_token(token_to_find);
    remove_entry(entry);
    return entry;
}

DelayQueueEntry *DelayQueue::find_entry_by_token(intptr_t token_to_find)
{
    DelayQueueEntry *cur = head();
    while (cur != this) {
        if (cur->token() == token_to_find) return cur;
        cur = cur->m_next;
    }
    return NULL;
}

const timeval DelayQueue::time_to_next_alarm()
{
    if (head()->m_delta_time_remaining == DELAY_ZERO)
        return DELAY_ZERO;

    synchronize();
    return head()->m_delta_time_remaining;
}

void DelayQueue::handle_alarm()
{
    if (head()->m_delta_time_remaining != DELAY_ZERO)
        synchronize();

    if (head()->m_delta_time_remaining == DELAY_ZERO) {
        DelayQueueEntry *to_remove = head();
        remove_entry(to_remove);
        to_remove->handle_timeout();
    }
}

TaskScheduler::TaskScheduler(unsigned max_scheduler_granularity) :
    m_max_scheduler_granularity(max_scheduler_granularity),
    m_max_num_sockets(0),
    m_last_handled_socket_num(-1),
    m_watch_variable(NULL)
{
    FD_ZERO(&m_read_set);
    FD_ZERO(&m_write_set);
    FD_ZERO(&m_exception_set);

    m_handlers = new HandlerSet;
}

TaskScheduler::~TaskScheduler()
{
    SAFE_DELETE(m_handlers);
}

int TaskScheduler::do_event_loop(volatile bool *watch_variable)
{
    m_watch_variable = watch_variable;
    for ( ; ; ) {
        if (m_watch_variable && *m_watch_variable)
            break;
        if (single_step() < 0)
            return -1;
    }
    return 0;
}

int TaskScheduler::single_step(unsigned max_delay_time)
{
    fd_set read_set = m_read_set;
    fd_set write_set = m_write_set;
    fd_set exception_set = m_exception_set;

    struct timeval tv = m_delay_queue.time_to_next_alarm();
    const long MAX_TV_SEC = MILLION;
    if (tv.tv_sec > MAX_TV_SEC)
        tv.tv_sec = MAX_TV_SEC;
    if (max_delay_time > 0 &&
        (tv.tv_sec > (long) max_delay_time/MILLION ||
         (tv.tv_sec == (long) max_delay_time/MILLION &&
          tv.tv_usec > (long) max_delay_time%MILLION))) {
        tv.tv_sec = max_delay_time/MILLION;
        tv.tv_usec = max_delay_time%MILLION;
    }

    int res = select(m_max_num_sockets, &read_set, &write_set, &exception_set, &tv);
    if (res < 0) {
        if (errno != EINTR && errno != EAGAIN) {
            LOGE("single_step(): select() failes: %s", ERRNOMSG);
            return -1;
        }
        return 0;
    }

    HandlerSet::Iterator it = m_handlers->begin();
    if (m_last_handled_socket_num >= 0) {
        while (it != m_handlers->end()) {
            if ((*it)->socket_num == m_last_handled_socket_num)
                break;
            ++it;
        }
        if (it == m_handlers->end()) {
            m_last_handled_socket_num = -1;
            it = m_handlers->begin();
        } else {
            ++it;
        }
    }
    while (it != m_handlers->end()) {
        int sock = (*it)->socket_num;
        int result_condition_set = 0;
        if (FD_ISSET(sock, &read_set) && FD_ISSET(sock, &m_read_set))
            result_condition_set |= SOCKET_READABLE;
        if (FD_ISSET(sock, &write_set) && FD_ISSET(sock, &m_write_set))
            result_condition_set |= SOCKET_WRITABLE;
        if (FD_ISSET(sock, &exception_set) && FD_ISSET(sock, &m_exception_set))
            result_condition_set |= SOCKET_EXCEPTION;
        if ((result_condition_set&(*it)->condition_set) != 0 &&
            (*it)->handler_proc != NULL) {
            m_last_handled_socket_num = sock;
            ((*it)->handler_proc)((*it)->client_data, result_condition_set);
            break;
        }
        ++it;
    }
    if (it == m_handlers->end() && m_last_handled_socket_num >= 0) {
        it = m_handlers->begin();
        while (it != m_handlers->end()) {
            int sock = (*it)->socket_num;
            int result_condition_set = 0;
            if (FD_ISSET(sock, &read_set) && FD_ISSET(sock, &m_read_set))
                result_condition_set |= SOCKET_READABLE;
            if (FD_ISSET(sock, &write_set) && FD_ISSET(sock, &m_write_set))
                result_condition_set |= SOCKET_WRITABLE;
            if (FD_ISSET(sock, &exception_set) && FD_ISSET(sock, &m_exception_set))
                result_condition_set |= SOCKET_EXCEPTION;
            if ((result_condition_set&(*it)->condition_set) != 0 &&
                    (*it)->handler_proc != NULL) {
                m_last_handled_socket_num = sock;
                ((*it)->handler_proc)((*it)->client_data, result_condition_set);
                break;
            }
            ++it;
        }
        if (it == m_handlers->end())
            m_last_handled_socket_num = -1;
    }

    m_delay_queue.handle_alarm();
    return 0;
}

void TaskScheduler::set_background_handling(int socket_num,
        int condition_set, BackgroundHandlerProc *handler_proc, void *client_data)
{
    if (socket_num < 0) return;
    FD_CLR((unsigned) socket_num, &m_read_set);
    FD_CLR((unsigned) socket_num, &m_write_set);
    FD_CLR((unsigned) socket_num, &m_exception_set);
    if (!condition_set) {
        m_handlers->clear_handler(socket_num);
        if (socket_num + 1 == m_max_num_sockets)
            --m_max_num_sockets;
    } else {
        m_handlers->assign_handler(socket_num, condition_set, handler_proc, client_data);
        if (socket_num + 1 > m_max_num_sockets)
            m_max_num_sockets = socket_num + 1;
        if (condition_set&SOCKET_READABLE) FD_SET((unsigned)socket_num, &m_read_set);
        if (condition_set&SOCKET_WRITABLE) FD_SET((unsigned)socket_num, &m_write_set);
        if (condition_set&SOCKET_EXCEPTION) FD_SET((unsigned)socket_num, &m_exception_set);
    }
}

TaskToken TaskScheduler::schedule_delayed_task(int64_t microseconds, TaskFunc *proc,
        void *client_data)
{
    if (microseconds < 0) microseconds = 0;
    struct timeval tv = {(long)microseconds/MILLION, (long)microseconds%MILLION};
    AlarmHandler *alarm_handler = new AlarmHandler(proc, client_data, tv);
    m_delay_queue.add_entry(alarm_handler);
    return (void *)(alarm_handler->token());
}

void TaskScheduler::unschedule_delayed_task(TaskToken &prev_task)
{
    DelayQueueEntry *alarm_handler = m_delay_queue.remove_entry((intptr_t) prev_task);
    prev_task = NULL;
    delete alarm_handler;
}

HandlerSet::HandlerSet()
{
}

HandlerSet::~HandlerSet()
{
    FOR_VECTOR_ITERATOR(HandlerDescriptor *, m_handlers, it) {
        SAFE_DELETE((*it));
    }
    m_handlers.clear();
}

void HandlerSet::assign_handler(int socket_num, int condition_set,
        TaskScheduler::BackgroundHandlerProc *handler_proc, void *client_data)
{
    HandlerDescriptor *handler = NULL;
    FOR_VECTOR_ITERATOR(HandlerDescriptor *, m_handlers, it) {
        if ((*it)->socket_num == socket_num) {
            handler = (*it);
            break;
        }
    }
    if (!handler) {
        handler = new HandlerDescriptor;
        m_handlers.push_back(handler);
        handler->socket_num = socket_num;
    }
    handler->condition_set = condition_set;
    handler->handler_proc = handler_proc;
    handler->client_data = client_data;
}

void HandlerSet::clear_handler(int socket_num)
{
    FOR_VECTOR_ITERATOR(HandlerDescriptor *, m_handlers, it) {
        if ((*it)->socket_num == socket_num) {
            SAFE_DELETE(*it);
            m_handlers.erase(it);
            break;
        }
    }
}

void HandlerSet::move_handler(int old_socket_num, int new_socket_num)
{
    HandlerDescriptor *handler = NULL;
    FOR_VECTOR_ITERATOR(HandlerDescriptor *, m_handlers, it) {
        if ((*it)->socket_num == old_socket_num) {
            handler = (*it);
            break;
        }
    }
    if (handler) {
        handler->socket_num = new_socket_num;
    }
}

RtspClient::RtspClient(void *opaque) :
    m_user_agent_str(DEFAULT_USER_AGENT),
    m_base_url(NULL),
    m_desired_max_incoming_packet_size(0),
    m_session_timeout_parameter(0),
    m_duration(0.0),
    m_last_session_id(NULL),
    m_liveness_command_task(NULL),
    m_stream_timer_task(NULL),
    m_sess(NULL),
    m_server_supports_get_parameter(false),
    m_opaque(opaque),
    m_tcp_stream_id_count(0)
{
    m_scheduler = new TaskScheduler;
}

RtspClient::~RtspClient()
{
    SAFE_FREE(m_base_url);
    SAFE_FREE(m_last_session_id);
    SAFE_DELETE(m_sess);
    m_scheduler->unschedule_delayed_task(m_liveness_command_task);
    m_scheduler->unschedule_delayed_task(m_stream_timer_task);
    SAFE_DELETE(m_scheduler);
}

void RtspClient::close()
{
    Tcp::close();
    m_stat = StateInit;
}

int RtspClient::open(const std::string &url,
        AddressPort &ap)
{
    if (m_stat != StateInit)
        return -1;

    RtspUrl _url;
    if (Rtsp::parse_url(url, _url) < 0)
        return -1;

    m_base_url = strdup(STR(_url.to_string()));

#ifdef XDEBUG
    LOGD("rtsp_url is: %s", m_base_url);
#endif

    if (Tcp::open(ap) < 0)
        return -1;

    if (Tcp::connect(_url.srvap) < 0)
        return -1;

    LOGI("Connected to rtsp server: %s successfully",
         STR(_url.srvap.to_string()));

    m_stat = StateConnected;
    return 0;
}

int RtspClient::request_options(TaskFunc *proc)
{
    if (m_stat < StateConnected)
        return -1;

    if (send_request(STR(generate_cmd_url(m_base_url, NULL)), "OPTIONS") < 0)
        return -1;

    ResponseInfo ri;
    if (recv_response(&ri) < 0)
        return -1;

    m_server_supports_get_parameter = rtsp_option_is_supported(
            "GET_PARAMETER", ri.public_parm_str);

    if (proc) proc(this);
    return 0;
}

int RtspClient::request_describe(std::string &sdp, TaskFunc *proc)
{
    if (m_stat < StateConnected)
        return -1;

    add_field("Accept: application/sdp");
    if (send_request(STR(generate_cmd_url(m_base_url, NULL)), "DESCRIBE") < 0)
        return -1;

    ResponseInfo ri;
    if (recv_response(&ri) < 0)
        return -1;

    if (strncasecmp(ri.content_type_parm_str, "application/sdp", 15)) {
        LOGE("Describe's content-type is not application/sdp");
        return -1;
    }
    sdp.assign(ri.body_start, ri.num_body_bytes);

    if (proc) proc(this);
    return 0;
}

int RtspClient::send_request(const char *cmd_url, const std::string &request, const std::string &content)
{
    ++m_cseq;
    string str(sprintf_("%s %s RTSP/1.0"CRLF
                              "CSeq: %d"CRLF
                              "User-Agent: %s"CRLF
                              "%s"
                              CRLF
                              "%s",
            STR(request), cmd_url,
            m_cseq,
            STR(m_user_agent_str),
            STR(field2string()),
            STR(content)));
#ifdef XDEBUG_RTSP_MESSAGE
    LOGD("Sent rtsp request:[%s]", STR(str));
#endif
    m_fields.clear();
    return Tcp::write((const uint8_t *) STR(str), str.length());
}

int RtspClient::recv_response(ResponseInfo *pri)
{
    for ( ; ; ) {
        int nread;
        if ((nread = read(m_rrb.buf+m_rrb.nread, m_rrb.get_max_bufsz()-m_rrb.nread)) < 0)
            return -1;
        m_rrb.nread += nread;

        bool end_of_headers = false;
        const uint8_t *ptr = m_rrb.buf;
        if (m_rrb.nread > 3) {
            uint8_t const *const ptr_end = &m_rrb.buf[m_rrb.nread-3];
            while (ptr < ptr_end) {
                if (*ptr++ == '\r' && *ptr++ == '\n' && *ptr++ == '\r' && *ptr++ == '\n') {
                    end_of_headers = true;
                    break;
                }
            }
        }

        if (end_of_headers) {
            m_rrb.buf[m_rrb.nread] = '\0';
            break;
        }
    }

#ifdef XDEBUG_RTSP_MESSAGE
    LOGD("Recvd rtsp response:[%s]", m_rrb.buf);
#endif

    char *header_data_copy;
    int ret = 0;

    do {
        header_data_copy = (char *) malloc(RTSP_MSG_BUFSIZ);
        strncpy(header_data_copy, (char *) m_rrb.buf, m_rrb.nread);
        header_data_copy[m_rrb.nread] = '\0';

        char *line_start;
        char *next_line_start = header_data_copy;
        do {
            line_start = next_line_start;
            next_line_start = get_line(line_start);
        } while (line_start[0] == '\0' && next_line_start != NULL);

        if (!parse_response_code(line_start, pri->response_code, pri->response_str)) {
            LOGE("Parse response code failed");
            ret = -1;
            break;
        }

        bool reach_end_of_headers;
        unsigned cseq;
        unsigned content_length = 0;
        for ( ; ; ) {
            reach_end_of_headers = true;
            line_start = next_line_start;
            if (!line_start) break;

            next_line_start = get_line(line_start);
            if (line_start[0] == '\0') break;
            reach_end_of_headers = false;

            char *header_parm_str = NULL;
            if (check_for_header(line_start, "CSeq:", 5, header_parm_str)) {
                if (sscanf(header_parm_str, "%u", &cseq) != 1 || cseq <= 0) {
                    LOGE("Bad \"CSeq\" header: \"%s\"", line_start);
                    break;
                }
                SAFE_FREE(header_parm_str);
            } else if (check_for_header(line_start, "Content-Length:", 15, header_parm_str)) {
                if (sscanf(header_parm_str, "%u", &content_length) != 1) {
                    LOGE("Bad \"Content-Length:\" header: \"%s\"", line_start);
                    break;
                }
                SAFE_FREE(header_parm_str);
            } else if (check_for_header(line_start, "Session:", 8, pri->session_parm_str)) {
            } else if (check_for_header(line_start, "Transport:", 10, pri->transport_parm_str)) {
            } else if (check_for_header(line_start, "Scale:", 6, pri->scale_parm_str)) {
            } else if (check_for_header(line_start, "Range:", 6, pri->range_parm_str)) {
            } else if (check_for_header(line_start, "RTP-Info:", 9, pri->rtp_info_parm_str)) {
            } else if (check_for_header(line_start, "Public:", 7, pri->public_parm_str)) {
            } else if (check_for_header(line_start, "Content-Base:", 13, pri->content_base_parm_str)) {
            } else if (check_for_header(line_start, "Content-Type:", 13, pri->content_type_parm_str)) {
            }
        }
        if (!reach_end_of_headers) {
            ret = -1;
            break;
        }

#ifdef XDEBUG_RTSP_MESSAGE
        LOGD("response_code: %u, response_str:%s, session_parm_str:%s, transport_parm_str:%s, scale_parm_str:%s, range_parm_str:%s, rtp_info_parm_str:%s, public_parm_str:%s, content_base_parm_str:%s, content_type_parm_str:%s",
                pri->response_code, pri->response_str, pri->session_parm_str, pri->transport_parm_str, pri->scale_parm_str, pri->range_parm_str, pri->rtp_info_parm_str, pri->public_parm_str, pri->content_base_parm_str, pri->content_type_parm_str);
#endif

        unsigned body_offset = next_line_start == NULL ?
            m_rrb.nread : next_line_start - header_data_copy;
        if (content_length) {
            pri->num_body_bytes = m_rrb.nread - body_offset;
            pri->body_start = (char *) malloc(content_length);
            memcpy(pri->body_start, &m_rrb.buf[body_offset], pri->num_body_bytes);
            if (content_length > pri->num_body_bytes) {
                unsigned num_extra_bytes_needed = content_length - pri->num_body_bytes;
                unsigned remaining_buffer_size = m_rrb.get_max_bufsz() - m_rrb.nread;
                if (num_extra_bytes_needed > remaining_buffer_size) {
                    LOGW("Response buffer size (%d) is too small for \"Content-Length:\" %d",
                            RTSP_MSG_BUFSIZ, content_length);
                    ret = -1;
                    break;
                }

                // Read num_extra_bytes_needed bytes to fill |Content-Length|
                LOGW("!Need to read more bytes to fill \"Content-Length\"");
                int n2read = num_extra_bytes_needed;
                if (readn(m_rrb.buf+m_rrb.nread, n2read) != n2read) {
                    ret = -1;
                    break;
                }
                memcpy(pri->body_start+pri->num_body_bytes, m_rrb.buf+m_rrb.nread, n2read);
                pri->num_body_bytes += n2read;
                m_rrb.reset();
                break;
            }
        }

        int num_extra_bytes_after_response =
            m_rrb.nread - (body_offset + content_length);
        if (num_extra_bytes_after_response != 0) {
            LOGD("Extra bytes(%d) after one rtsp response",
                    num_extra_bytes_after_response);
            memmove(m_rrb.buf, m_rrb.buf+body_offset+content_length,
                    num_extra_bytes_after_response);
            m_rrb.nread = num_extra_bytes_after_response;
        } else {
            m_rrb.reset();
        }
    } while (0);

    SAFE_FREE(header_data_copy);
    if (ret < 0 || pri->response_code != 200) {
        pri->reset();
        ret = -1;
    }
    return ret;
}

char *RtspClient::get_line(char *start_of_line)
{
    for (char* ptr = start_of_line; *ptr != '\0'; ++ptr) {
        if (*ptr == '\r' || *ptr == '\n') {
            if (*ptr == '\r') {
                *ptr++ = '\0';
                if (*ptr == '\n') ++ptr;
            } else {
                *ptr++ = '\0';
            }
            return ptr;
        }
    }

    return NULL;
}

bool RtspClient::parse_response_code(char *line,
        unsigned &response_code, char *&response_string)
{
    if (sscanf(line, "RTSP/%*s%u", &response_code) != 1)
        return false; 

    char *p = line;
    while (p[0] != '\0' &&
           p[0] != ' '  &&
           p[0] != '\t')
        ++p;
    while (p[0] != '\0' &&
           (p[0] == ' '  || p[0] == '\t'))
        ++p;
    response_string = strdup(p);
    return true; 
}

bool RtspClient::check_for_header(char *line,
        char const *header_name, unsigned header_name_length,
        char *&header_parm)
{
    if (strncasecmp(line, header_name, header_name_length))
        return false;

    unsigned parm_index = header_name_length;
    while (line[parm_index] != '\0' &&
           (line[parm_index] == ' ' || line[parm_index] == '\t'))
        ++parm_index;
    if (line[parm_index] == '\0') return false;

    SAFE_FREE(header_parm);
    header_parm = strdup(&line[parm_index]);
    return true;
}

char *create_session_string(const char *session_id)
{
    char *session_str;
    if (session_id) {
        session_str = (char *) malloc(20 + strlen(session_id));
        sprintf(session_str, "Session: %s", session_id);
    } else
        session_str = strdup("");
    return session_str;
}

char *RtspClient::create_blocksize_string(bool stream_using_tcp)
{
    char *blocksize_str;
    uint16_t max_packet_size = m_desired_max_incoming_packet_size;

    const uint16_t header_allowance = stream_using_tcp ? 12 : 50;
    if (max_packet_size < header_allowance)
        max_packet_size = 0;
    else
        max_packet_size -= header_allowance;

    if (max_packet_size > 0) {
        blocksize_str = (char *) malloc(25);
        sprintf(blocksize_str, "Blocksize: %u", max_packet_size);
    } else
        blocksize_str = strdup("");
    return blocksize_str;
}

string RtspClient::generate_cmd_url(const char *base_url,
                                    MediaSession *session, MediaSubsession *subsession)
{
    if (subsession) {
        const char *prefix, *separator, *suffix;
        construct_subsession_url(*subsession, prefix, separator, suffix);

        return sprintf_("%s%s%s", prefix, separator, suffix);
    } else if (session)
        return session_url(*session);
    else
        return base_url;
}

int RtspClient::request_setup(const std::string &sdp, bool stream_outgoing, bool stream_using_tcp)
{
    m_sess = MediaSession::create_new(this, STR(sdp), m_opaque);
    if (!m_sess) {
        LOGE("Create MediaSession failed");
        return -1;
    }
    return m_sess->setup_subsessions(stream_outgoing, stream_using_tcp);
}

int RtspClient::request_play()
{
    if (m_sess->play_subsessions() == 0) {
        if (m_duration > 0) {
            const unsigned delay_slop = 2;
            m_duration += delay_slop;
            unsigned u_secs_to_delay = m_duration*MILLION;
            m_stream_timer_task = m_scheduler->schedule_delayed_task(
                    u_secs_to_delay, (TaskFunc *) stream_timer_handler, this);
        }
        LOGI("Started playing session (for up to %.3lf seconds) ...",
                m_duration);
        return 0;
    }
    return (-1);
}

int RtspClient::request_teardown()
{
    if (!m_last_session_id) {
        LOGE("No RTSP session is currently in progress");
        return -1;
    }

    string cmd_url(generate_cmd_url(m_base_url, m_sess));

    char *session_str = create_session_string(m_last_session_id);
    add_field(session_str);
    SAFE_FREE(session_str);

    if (send_request(STR(cmd_url), "TEARDOWN") > 0) {
        ResponseInfo ri;
        if (!recv_response(&ri)) {
            m_stat = StateInit;
        }
    }
    return 0;
}

int RtspClient::request_get_parameter(TaskFunc *proc)
{
    if (!m_last_session_id) {
        LOGE("No RTSP session is currently in progress");
        return -1;
    }

    string cmd_url(generate_cmd_url(m_base_url, m_sess));

    char *session_str = create_session_string(m_last_session_id);
    add_field(session_str);
    SAFE_FREE(session_str);

    if (send_request(STR(cmd_url), "GET_PARAMETER") > 0) {
        ResponseInfo ri;
        if (!recv_response(&ri)) {
            m_stat = StateInit;
        }
    }

    if (proc) proc(this);
    return 0;
}

int RtspClient::request_announce(const std::string &sdp)
{
    if (m_stat < StateConnected)
        return -1;

    add_field("Content-Type: application/sdp");
    add_field(sprintf_("Content-Length: %d", sdp.length()));
    string cmd_url(generate_cmd_url(m_base_url, NULL));

    if (send_request(STR(cmd_url), "ANNOUNCE", sdp) > 0) {
        ResponseInfo ri;
        if (!recv_response(&ri)) {
            m_stat = StateInit;
        }
    }
    return 0;
}

void RtspClient::continue_after_get_parameter(void *client_data)
{
    ((RtspClient *) client_data)->schedule_liveness_command();
}

int RtspClient::request_setup(MediaSubsession &subsession,
        bool stream_outgoing, bool stream_using_tcp, bool force_multicast_on_unspecified)
{
    string cmd_url(generate_cmd_url(m_base_url, NULL, &subsession));

    const char *transport_fmt;
    if (!strcmp(subsession.protocol_name(), "UDP"))
        transport_fmt = "Transport: RAW/RAW/UDP%s%s%s=%d-%d";
    else
        transport_fmt = "Transport: RTP/AVP%s%s%s=%d-%d";

    const char *transport_type_str;
    const char *mode_str = stream_outgoing ? ";mode=receive" : "";
    const char *port_type_str;
    PortNumBits rtp_number, rtcp_number;
    if (stream_using_tcp) {
        transport_type_str = "/TCP;unicast";
        port_type_str = ";interleaved";
        rtp_number = m_tcp_stream_id_count++;
        rtcp_number = m_tcp_stream_id_count++;
    } else {
        unsigned conn_address = subsession.connection_endpoint_address();
        bool request_multicast_streaming =
            is_multicast_address(conn_address) || (!conn_address && force_multicast_on_unspecified);
        transport_type_str = request_multicast_streaming ? ";multicast" : ";unicast";
        port_type_str = ";client_port";
        rtp_number = subsession.client_port_num();
        if (!rtp_number) {
            LOGE("Client port number unknown");
            return -1;
        }
        rtcp_number = subsession.rtcp_is_muxed() ? rtp_number : rtp_number + 1;
    }

    unsigned transport_size = strlen(transport_fmt) +
        strlen(transport_type_str) + strlen(mode_str) + strlen(port_type_str) + 2*5;
    char *transport_str = (char *) malloc(transport_size);
    sprintf(transport_str, transport_fmt,
            transport_type_str, mode_str, port_type_str, rtp_number, rtcp_number);

    char *session_str = create_session_string(m_last_session_id);

    char *blocksize_str = create_blocksize_string(stream_using_tcp);

    add_field(transport_str);
    add_field(session_str);
    add_field(blocksize_str);
    SAFE_FREE(transport_str); SAFE_FREE(session_str); SAFE_FREE(blocksize_str);

    if (send_request(STR(cmd_url), "SETUP") > 0) {
        ResponseInfo ri;
        if (!recv_response(&ri)) {
            char *session_id = (char *) malloc(strlen(ri.session_parm_str) + 1);
            if (session_id) {
                do {
                    if (!ri.session_parm_str ||
                        sscanf(ri.session_parm_str, "%[^;]", session_id) != 1) {
                        LOGE("Missing or bad \"Session:\" header");
                        break;
                    }
                    subsession.set_session_id(session_id);
                    SAFE_FREE(m_last_session_id); m_last_session_id = strdup(session_id);

                    const char *after_session_id = ri.session_parm_str + strlen(session_id);
                    int timeout_val;
                    if (sscanf(after_session_id, ";timeout=%d", &timeout_val) == 1)
                        m_session_timeout_parameter = timeout_val;
                } while (0);
                SAFE_FREE(session_id);
            } else {
                LOGE("malloc for session_id failed: %s", ERRNOMSG);
                return -1;
            }

            char *server_address_str;
            PortNumBits server_port_num;
            if (parse_transport_parms(ri.transport_parm_str,
                        server_address_str, server_port_num) < 0) {
                LOGE("Missing or bad \"Transport:\" header");
                return -1;
            }
            SAFE_FREE(subsession.connection_endpoint_name());
            subsession.connection_endpoint_name() = server_address_str;
            subsession.server_port_num() = server_port_num;

            m_stat = StateReady;
        }
    }
    return 0;
}

int RtspClient::parse_transport_parms(const char *parms_str,
        char *&server_address_str, PortNumBits &server_port_num)
{
    server_address_str = NULL;
    server_port_num = 0;
    if (!parms_str || !strlen(parms_str)) return -1;

    char *found_server_address_str = NULL;
    bool found_server_port_num = false;
    PortNumBits client_port_num = 0;
    bool found_client_port_num = false;
    bool is_multicast = true;
    char *found_destination_str = NULL;
    PortNumBits multicast_port_num_rtp, multicast_port_num_rtcp;
    bool found_multicast_port_num = false;
    unsigned rtp_cid, rtcp_cid;
    bool found_channel_ids = false;
    unsigned char rtp_channel_id, rtcp_channel_id;

    const char *fields = parms_str;
    char *field = (char *) malloc(strlen(fields) + 1);
    while (sscanf(fields, "%[^;]", field) == 1) {
        if (sscanf(field, "server_port=%hu", &server_port_num) == 1) {
            found_server_port_num = true;
        } else if (sscanf(field, "client_port=%hu", &client_port_num) == 1) {
            found_client_port_num = true;
        } else if (strncasecmp(field, "source=", 7) == 0) {
            SAFE_FREE(found_server_address_str);
            found_server_address_str = strdup(field + 7);
        } else if (sscanf(field, "interleaved=%u-%u", &rtp_cid, &rtcp_cid) == 2) {
            rtp_channel_id = (unsigned char ) rtp_cid;
            rtcp_channel_id = (unsigned char ) rtcp_cid;
            found_channel_ids = true;
        } else if (strcmp(field, "unicast") == 0) {
            is_multicast = false;
        } else if (strncasecmp(field, "destination=", 12) == 0) {
            SAFE_FREE(found_destination_str);
            found_destination_str = strdup(field + 12);
        } else if (sscanf(field, "port=%hu-%hu", &multicast_port_num_rtp, &multicast_port_num_rtcp) == 2 ||
                sscanf(field, "port=%hu", &multicast_port_num_rtp) == 1) {
            found_multicast_port_num = true;
        }

        fields += strlen(field);
        while (fields[0] == ';') ++fields; // Skip over all leading ';' chars
        if (fields[0] == '\0') break;
    }
    SAFE_FREE(field);

    if (is_multicast && found_destination_str && found_multicast_port_num) {
        SAFE_FREE(found_server_address_str);
        server_address_str = found_destination_str;
        server_port_num = multicast_port_num_rtp;
        return 0;
    }
    SAFE_FREE(found_destination_str);

    if (found_channel_ids || found_server_port_num || found_client_port_num) {
        if (found_client_port_num && !found_server_port_num)
            server_port_num = client_port_num;
        server_address_str = found_server_address_str;
        return 0;
    }

    SAFE_FREE(found_server_address_str);
    return -1;
}

static char *create_scale_string(float scale, float current_scale)
{
    char buf[100];

    if (scale == 1.0f && current_scale == 1.0f)
        buf[0] = '\0';
    else
        sprintf(buf, "Scale: %f", scale);

    return strdup(buf);
}

static char *create_range_string(double start, double end,
        const char *abs_start_time, const char *abs_end_time)
{
    char buf[100];

    if (abs_start_time != NULL) {
        if (abs_end_time == NULL)
            snprintf(buf, sizeof buf, "Range: clock=%s-", abs_start_time);
        else
            snprintf(buf, sizeof buf, "Range: clock=%s-%s", abs_start_time, abs_end_time);
    } else {
        if (start < 0)
            buf[0] = '\0';
        else if (end < 0)
            sprintf(buf, "Range: npt=%.3f-", start);
        else
            sprintf(buf, "Range: npt=%.3f-%.3f", start, end);
    }

    return strdup(buf);
}

int RtspClient::request_play(MediaSession &session,
        double start, double end, float scale)
{
    if (!m_last_session_id) {
        LOGE("No RTSP session is currently in progress");
        return -1;
    }

    string cmd_url(generate_cmd_url(m_base_url, &session));

    char *session_str = create_session_string(m_last_session_id);
    char *scale_str = create_scale_string(scale, session.scale());
    char *range_str = create_range_string(start, end, NULL, NULL);
    add_field(session_str);
    add_field(scale_str);
    add_field(range_str);
    SAFE_FREE(session_str); SAFE_FREE(scale_str); SAFE_FREE(range_str);

    if (send_request(STR(cmd_url), "PLAY") > 0) {
        ResponseInfo ri;
        if (!recv_response(&ri)) {
            m_stat = StatePlaying;
        }
    }
    return 0;
}

static bool is_absolute_url(char const* url) {
  while (*url != '\0' && *url != '/') {
    if (*url == ':') return true;
    ++url;
  }
  return false;
}

void RtspClient::construct_subsession_url(MediaSubsession const &subsession,
        const char *&prefix, const char *&separator, const char *&suffix)
{
    prefix = session_url(subsession.parent_session());
    if (!prefix) prefix = "";

    suffix = subsession.control_path();
    if (!suffix) suffix = "";

    if (is_absolute_url(suffix)) {
        prefix = separator = "";
    } else {
        unsigned prefix_len = strlen(prefix);
        separator = (prefix_len == 0 || prefix[prefix_len-1] == '/' || suffix[0] == '/') ? "" : "/";
    }
}

const char *RtspClient::session_url(MediaSession const &session) const
{
    const char *url = session.control_path();
    if (url == NULL || strcmp(url, "*") == 0) url = m_base_url;
    return url;
}

int RtspClient::loop(volatile bool *watch_variable)
{
    return m_scheduler->do_event_loop(watch_variable);
}

void RtspClient::schedule_liveness_command()
{
    unsigned delay_max = m_session_timeout_parameter;
    if (!delay_max)
        delay_max = 60;

    const unsigned us_1st_part = delay_max*500000;
    unsigned u_seconds_to_delay;
    if (us_1st_part <= 1000000)
        u_seconds_to_delay = us_1st_part;
    else {
        const unsigned us_2nd_part = us_1st_part - 1000000;
        u_seconds_to_delay = us_1st_part + (us_2nd_part*random())%us_2nd_part;
    }

#ifdef XDEBUG
    LOGD("Will send_liveness_command() in %.2f secs",
            ((double) u_seconds_to_delay)/MILLION);
#endif

    if (m_liveness_command_task)
        m_scheduler->unschedule_delayed_task(m_liveness_command_task);
    m_liveness_command_task = m_scheduler->schedule_delayed_task(
            u_seconds_to_delay, send_liveness_command, this);
}

void RtspClient::send_liveness_command(void *client_data)
{
    RtspClient *rtsp_client = (RtspClient *) client_data;
    if (rtsp_client->m_server_supports_get_parameter)
        rtsp_client->request_get_parameter(continue_after_get_parameter);
    else
        rtsp_client->request_options(continue_after_option);
}

void RtspClient::continue_after_option(void *client_data)
{
    RtspClient *rtsp_client = (RtspClient *) client_data;
    if (!rtsp_client->m_server_supports_get_parameter)
        rtsp_client->schedule_liveness_command();
}

void RtspClient::continue_after_describe(void *client_data)
{
    RtspClient *rtsp_client = (RtspClient *) client_data;
    rtsp_client->schedule_liveness_command();
}

void RtspClient::stream_timer_handler(void *client_data)
{
    RtspClient *rtsp_client = (RtspClient *) client_data;
    rtsp_client->m_stream_timer_task = NULL;
    shutdown_stream(rtsp_client);
}

void RtspClient::shutdown_stream(RtspClient *rtsp_client)
{
    if (rtsp_client->request_teardown() < 0) {
        LOGE("Failed to send TEARDOWN command (cont)");
    }
    rtsp_client->m_scheduler->ask2quit();
}

bool RtspClient::rtsp_option_is_supported(const char *command_name,
        const char *public_parm_str)
{
    return !!strcasestr(public_parm_str, command_name);
}

SDPAttribute::SDPAttribute(char const* str_value, bool value_is_hexadecimal) :
    m_str_value(strdup(str_value)),
    m_str_value_to_lower(NULL),
    m_value_is_hexadecimal(value_is_hexadecimal) {
  if (!m_str_value) {
    m_int_value = 1;
  } else {
    int str_size = strlen(m_str_value) + 1;
  
    m_str_value_to_lower = (char *) malloc(str_size);
    if (!m_str_value_to_lower) {
        LOGE("malloc for m_str_value_to_lower failed: %s", ERRNOMSG);
        return;
    }
    for (int i = 0; i < str_size-1; ++i) m_str_value_to_lower[i] = tolower(m_str_value[i]);
    m_str_value_to_lower[str_size-1] = '\0';
    
    if (sscanf(m_str_value_to_lower, value_is_hexadecimal ? "%x" : "%d", &m_int_value) != 1) {
      m_int_value = 0;
    }
  }
} 
    
SDPAttribute::~SDPAttribute() {
    SAFE_FREE(m_str_value);
    SAFE_FREE(m_str_value_to_lower);
}

MediaSession::MediaSession(RtspClient *rtsp_client, void *opaque) :
    m_client(rtsp_client),
    m_sess_name(NULL),
    m_sess_desc(NULL),
    m_conn_endpoint_name(NULL),
    m_control_path(NULL),
    m_max_play_start_time(0.0f), m_max_play_end_time(0.0f),
    m_media_sess_type(NULL),
    m_source_filter_name(NULL),
    m_abs_start_time(NULL),
    m_abs_end_time(NULL),
    m_scale(1.0f),
    m_opaque(opaque)
{
    char CNAME[128] = {0};
    gethostname(CNAME, sizeof(CNAME));
    m_cname = strdup(CNAME);
}

MediaSession::~MediaSession()
{
    SAFE_FREE(m_sess_name);
    SAFE_FREE(m_sess_desc);
    SAFE_FREE(m_conn_endpoint_name);
    SAFE_FREE(m_control_path);
    SAFE_FREE(m_media_sess_type);
    SAFE_FREE(m_source_filter_name);
    SAFE_FREE(m_abs_start_time);
    SAFE_FREE(m_abs_end_time);
    SAFE_FREE(m_cname);

    FOR_VECTOR_ITERATOR(MediaSubsession *, m_subsessions, it) {
        SAFE_DELETE(*it);
    }
    m_subsessions.clear();
}

int MediaSession::initialize_with_sdp(const std::string &sdp)
{
    if (sdp.empty()) return -1;

    const char *sdp_line = STR(sdp);
    const char *next_sdp_line;
    for ( ; ; ) {
        if (parse_sdp_line(sdp_line, next_sdp_line) < 0) return -1;
        if (sdp_line[0] == 'm') break;
        sdp_line = next_sdp_line;
        if (!sdp_line) break;

        if (!parse_sdp_line_s(sdp_line)) continue;
        if (!parse_sdp_line_i(sdp_line)) continue;
        if (!parse_sdp_line_c(sdp_line)) continue;
        if (!parse_sdp_attr_control(sdp_line)) continue;
        if (!parse_sdp_attr_range(sdp_line)) continue;
        if (!parse_sdp_attr_type(sdp_line)) continue;
        if (!parse_sdp_attr_source_filter(sdp_line)) continue;
    }

    while (sdp_line != NULL) {
        MediaSubsession *subsession = create_new_media_subsession();
        if (!subsession) {
            LOGE("Unable to create new MediaSubsession");
            return -1;
        }

        char *medium_name = (char *) malloc(strlen(sdp_line) + 1);
        if (!medium_name) return -1;
        const char *protocol_name = NULL;
        unsigned payload_format;
        if ((sscanf(sdp_line, "m=%s %hu RTP/AVP %u", medium_name, &subsession->m_client_port_num, &payload_format) == 3 ||
             sscanf(sdp_line, "m=%s %hu/%*u RTP/AVP %u", medium_name, &subsession->m_client_port_num, &payload_format) == 3) &&
            payload_format <= 127) {
            protocol_name = "RTP";
        } else if ((sscanf(sdp_line, "m=%s %hu UDP %u", medium_name, &subsession->m_client_port_num, &payload_format) == 3 ||
                    sscanf(sdp_line, "m=%s %hu udp %u", medium_name, &subsession->m_client_port_num, &payload_format) == 3 ||
                    sscanf(sdp_line, "m=%s %hu RAW/RAW/UDP %u", medium_name, &subsession->m_client_port_num, &payload_format) == 3) &&
                   payload_format <= 127) {
            protocol_name = "UDP";
        } else {
            char *sdp_line_str;
            if (!next_sdp_line) {
                sdp_line_str = (char *) sdp_line;
            } else {
                sdp_line_str = strdup(sdp_line);
                sdp_line_str[next_sdp_line-sdp_line] = '\0';
            }
            LOGE("Bad SDP \"m=\" line: %s", sdp_line_str);
            if (sdp_line_str != (char *) sdp_line) SAFE_FREE(sdp_line_str);
            SAFE_FREE(medium_name);
            SAFE_FREE(subsession);
            for ( ; ; ) {
                sdp_line = next_sdp_line;
                if (!sdp_line) break;
                if (parse_sdp_line(sdp_line, next_sdp_line) < 0) return -1;
                if (sdp_line[0] == 'm') break;
            }
            continue;
        }

        m_subsessions.push_back(subsession);

        subsession->m_server_port_num = subsession->m_client_port_num;

        const char *start = sdp_line;
        subsession->m_saved_sdp_lines = strdup(start);

        subsession->m_medium_name = strdup(medium_name);
        SAFE_FREE(medium_name);
        subsession->m_protocol_name = strdup(protocol_name);
        subsession->m_rtp_payload_format = payload_format;

        for ( ; ; ) {
            sdp_line = next_sdp_line;
            if (!sdp_line) break;
            if (parse_sdp_line(sdp_line, next_sdp_line) < 0) return -1;
            if (sdp_line[0] == 'm') break;
            if (!subsession->parse_sdp_line_c(sdp_line)) continue;
            if (!subsession->parse_sdp_line_b(sdp_line)) continue;
            if (!subsession->parse_sdp_attr_rtpmap(sdp_line)) continue;
            if (!subsession->parse_sdp_attr_rtcpmux(sdp_line)) continue;
            if (!subsession->parse_sdp_attr_control(sdp_line)) continue;
            if (!subsession->parse_sdp_attr_range(sdp_line)) continue;
            if (!subsession->parse_sdp_attr_fmtp(sdp_line)) continue;
            if (!subsession->parse_sdp_attr_source_filter(sdp_line)) continue;
            if (!subsession->parse_sdp_attr_x_dimensions(sdp_line)) continue;
            if (!subsession->parse_sdp_attr_framerate(sdp_line)) continue;
        }
        if (sdp_line) subsession->m_saved_sdp_lines[sdp_line - start] = '\0';

        if (!subsession->m_codec_name) {
            subsession->m_codec_name = lookup_payload_format(
                    subsession->m_rtp_payload_format,
                    subsession->m_rtp_timestamp_frequency,
                    subsession->m_num_channels);
            if (!subsession->m_codec_name) {
                LOGE("Unknown codec name for RTP payload type",
                        STR(sprintf_("%d", subsession->m_rtp_payload_format)));
                return -1;
            }
        }

        if (!subsession->m_rtp_timestamp_frequency) {
            subsession->m_rtp_timestamp_frequency =
                guess_rtp_timestamp_frequency(subsession->m_medium_name, subsession->m_codec_name);
        }
    }
    return 0;
}

int MediaSession::parse_sdp_line(const char *input_line, const char *&next_line)
{
    next_line = NULL;
    for (const char *ptr = input_line; *ptr; ++ptr) {
        if (*ptr == '\r' || *ptr == '\n') {
            ++ptr;
            while (*ptr == '\r' || *ptr == '\n') ++ptr;
            next_line = ptr;
            if (next_line[0] == '\0') next_line = NULL;
            break;
        }
    }

    if (input_line[0] == '\r' || input_line[0] == '\n') return 0;
    if (strlen(input_line) < 2 || input_line[1] != '=' ||
        input_line[0] < 'a' || input_line[0] > 'z') {
        LOGE("Invalid sdp line: ", input_line);
        return -1;
    }

    return 0;
}

int MediaSession::parse_sdp_line_s(const char *sdp_line)
{
    int ret = -1;
    char *buffer = (char *) malloc(strlen(sdp_line) + 1);
    if (!buffer) return -1;
    if (sscanf(sdp_line, "i=%[^\r\n]", buffer) == 1) {
        ret = 0;
        SAFE_FREE(m_sess_name);
        m_sess_name = strdup(buffer);
#ifdef XDEBUG
        LOGD("media_sess_name: %s", m_sess_name);
#endif
    }
    SAFE_FREE(buffer);
    return ret;
}

int MediaSession::parse_sdp_line_i(const char *sdp_line)
{
    int ret = -1;
    char *buffer = (char *) malloc(strlen(sdp_line) + 1);
    if (!buffer) return -1;
    if (sscanf(sdp_line, "i=%[^\r\n]", buffer) == 1) {
        ret = 0;
        SAFE_FREE(m_sess_desc);
        m_sess_desc = strdup(buffer);
#ifdef XDEBUG
        LOGD("sess_desc: %s", m_sess_desc);
#endif
    }
    SAFE_FREE(buffer);
    return ret;
}

static char *parse_c_line(const char *sdp_line)
{
    char *retval = NULL;
    char *buffer = (char *) malloc(strlen(sdp_line) + 1);
    if (sscanf(sdp_line, "c=IN IP4 %[^/\r\n]", buffer) == 1)
        retval = strdup(buffer);
    SAFE_FREE(buffer);
    return retval;
}

int MediaSession::parse_sdp_line_c(const char *sdp_line)
{
    char *conn_endpoint_name = parse_c_line(sdp_line);
    if (conn_endpoint_name) {
        SAFE_FREE(m_conn_endpoint_name);
        m_conn_endpoint_name = conn_endpoint_name;
#ifdef XDEBUG
        LOGD("conn_endpoint_name: %s", m_conn_endpoint_name);
#endif
        return 0;
    }
    return -1;
}

int MediaSession::parse_sdp_attr_control(const char *sdp_line)
{
    int ret = -1;
    char *control_path = (char *) malloc(strlen(sdp_line) + 1);
    if (sscanf(sdp_line, "a=control: %s", control_path) == 1) {
        ret = 0;
        SAFE_FREE(m_control_path);
        m_control_path = strdup(control_path);
#ifdef XDEBUG
        LOGD("control_path: %s", m_control_path);
#endif
    }
    SAFE_FREE(control_path);
    return ret;
}

static int parse_range_attr(const char *sdp_line,
        double &start_time, double &end_time)
{
    int res = sscanf(sdp_line, "a=range: npt = %lg - %lg",
            &start_time, &end_time);
    if (res == 2) return 0;
    return -1;
}

int MediaSession::parse_sdp_attr_range(const char *sdp_line)
{
    int ret = -1;
    double play_start_time;
    double play_end_time;
    if (!parse_range_attr(sdp_line, play_start_time, play_end_time)) {
        ret = 0;
        if (play_start_time > m_max_play_start_time)
            m_max_play_start_time = play_start_time;
        if (play_end_time > m_max_play_end_time)
            m_max_play_end_time = play_end_time;
#ifdef XDEBUG
        LOGD("max_play_start_time: %lf, max_play_end_time: %lf",
                m_max_play_start_time, m_max_play_end_time);
#endif
    }
    return ret;
}

int MediaSession::parse_sdp_attr_type(const char *sdp_line)
{
    int ret = -1;
    char *buffer = (char *) malloc(strlen(sdp_line) + 1);
    if (sscanf(sdp_line, "a=type: %[^ \r\n]", buffer) == 1) {
        ret = 0;
        SAFE_FREE(m_media_sess_type);
        m_media_sess_type = strdup(buffer);
#ifdef XDEBUG
        LOGD("media_sess_type: %s", m_media_sess_type);
#endif
    }   
    SAFE_FREE(buffer);
    return ret;
}

static int parse_source_filter_attr(const char *sdp_line,
        char *&source_filter_name)
{
    int ret = -1;
    char *source_name = (char *) malloc(strlen(sdp_line) + 1);
    if (!source_name) return -1;
    if (sscanf(sdp_line, "a=source-filter: incl IN IP4 %*s %s",
                source_name) == 1) {
        ret = 0;
        SAFE_FREE(source_filter_name);
        source_filter_name = strdup(source_name);
#ifdef XDEBUG
        LOGD("source_filter_name: %s", source_filter_name);
#endif
    }
    SAFE_FREE(source_name);
    return ret;
}

int MediaSession::parse_sdp_attr_source_filter(const char *sdp_line)
{
    return parse_source_filter_attr(sdp_line, m_source_filter_name);
}

MediaSession *MediaSession::create_new(RtspClient *rtsp_client, const char *sdp, void *opaque)
{
    MediaSession *new_session = new MediaSession(rtsp_client, opaque);
    if (new_session) {
        if (new_session->initialize_with_sdp(sdp) < 0) {
            SAFE_DELETE(new_session);
            return NULL;
        }
    }
    return new_session;
}

int MediaSession::setup_subsessions(bool stream_outgoing, bool stream_using_tcp)
{
    AddressPort ap;
    if (get_local_address_from_sockfd(m_client->get_sockfd(), ap) < 0)
        return -1;

    FOR_VECTOR_ITERATOR(MediaSubsession *, m_subsessions, it) {
        if ((*it)->initiate(ap.get_address()) < 0) {
            LOGE("Failed to initiate the \"%s/%s\" subsession (cont)",
                    (*it)->medium_name(), (*it)->codec_name());
            continue;
        }
        if ((*it)->rtcp_is_muxed()) {
            LOGI("Initiated the \"%s/%s\" subsession (client port %d)",
                    (*it)->medium_name(), (*it)->codec_name(), (*it)->client_port_num());
        } else {
            LOGI("Initiated the \"%s/%s\" subsession (client ports %d-%d)",
                    (*it)->medium_name(), (*it)->codec_name(), (*it)->client_port_num(), (*it)->client_port_num()+1);
        }
        
        m_client->request_setup(*(*it), stream_outgoing, stream_using_tcp);
    }
    return 0;
}

int MediaSession::play_subsessions()
{
    if (abs_start_time()) {
        LOGE("The stream is indexed by 'absolute' time: %s, not supported",
                abs_start_time());
        return -1;
    } else {
        m_client->duration() = play_end_time() - play_start_time();
        return m_client->request_play(*this);
    }
}

char *MediaSession::abs_start_time() const
{
    if (m_abs_start_time) return m_abs_start_time;

    FOR_VECTOR_CONST_ITERATOR(MediaSubsession *, m_subsessions, it) {
        if ((*it)->_abs_start_time()) return (*it)->_abs_start_time();
    }
    return NULL;
}

char *MediaSession::abs_end_time() const
{
    if (m_abs_end_time) return m_abs_end_time;

    FOR_VECTOR_CONST_ITERATOR(MediaSubsession *, m_subsessions, it) {
        if ((*it)->_abs_end_time()) return (*it)->_abs_end_time();
    }
    return NULL;
}

MediaSubsession *MediaSession::create_new_media_subsession()
{
    return new MediaSubsession(*this);
}

char *MediaSession::lookup_payload_format(unsigned char rtp_payload_type,
        unsigned &freq, unsigned &nchannel)
{
    char const* temp = NULL;
    switch (rtp_payload_type) {
    case 0:  {temp = "PCMU";    freq = 8000;  nchannel = 1; break;}
    case 2:  {temp = "G726-32"; freq = 8000;  nchannel = 1; break;}
    case 3:  {temp = "GSM";     freq = 8000;  nchannel = 1; break;}
    case 4:  {temp = "G723";    freq = 8000;  nchannel = 1; break;}
    case 5:  {temp = "DVI4";    freq = 8000;  nchannel = 1; break;}
    case 6:  {temp = "DVI4";    freq = 16000; nchannel = 1; break;}
    case 7:  {temp = "LPC";     freq = 8000;  nchannel = 1; break;}
    case 8:  {temp = "PCMA";    freq = 8000;  nchannel = 1; break;}
    case 9:  {temp = "G722";    freq = 8000;  nchannel = 1; break;}
    case 10: {temp = "L16";     freq = 44100; nchannel = 2; break;}
    case 11: {temp = "L16";     freq = 44100; nchannel = 1; break;}
    case 12: {temp = "QCELP";   freq = 8000;  nchannel = 1; break;}
    case 14: {temp = "MPA";     freq = 90000; nchannel = 1; break;}
    case 15: {temp = "G728";    freq = 8000;  nchannel = 1; break;}
    case 16: {temp = "DVI4";    freq = 11025; nchannel = 1; break;}
    case 17: {temp = "DVI4";    freq = 22050; nchannel = 1; break;}
    case 18: {temp = "G729";    freq = 8000;  nchannel = 1; break;}
    case 25: {temp = "CELB";    freq = 90000; nchannel = 1; break;}
    case 26: {temp = "JPEG";    freq = 90000; nchannel = 1; break;}
    case 28: {temp = "NV";      freq = 90000; nchannel = 1; break;}
    case 31: {temp = "H261";    freq = 90000; nchannel = 1; break;}
    case 32: {temp = "MPV";     freq = 90000; nchannel = 1; break;}
    case 33: {temp = "MP2T";    freq = 90000; nchannel = 1; break;}
    case 34: {temp = "H263";    freq = 90000; nchannel = 1; break;}
    };
    return strdup(temp);
}

unsigned MediaSession::guess_rtp_timestamp_frequency(
        const char *medium_name, const char *codec_name)
{
    if (strcmp(codec_name, "L16") == 0) return 44100;
    if (strcmp(codec_name, "MPA") == 0 ||
        strcmp(codec_name, "MPA-ROBUST") == 0 ||
        strcmp(codec_name, "X-MP3-DRAFT-00") == 0) return 90000;

    if (strcmp(medium_name, "video") == 0) return 90000;
    else if (strcmp(medium_name, "text") == 0) return 1000;
    return 8000;
}

MediaSubsession::MediaSubsession(MediaSession &parent) :
    m_parent(parent),
    m_client_port_num(0),
    m_server_port_num(0),
    m_saved_sdp_lines(NULL),
    m_medium_name(NULL),
    m_protocol_name(NULL),
    m_rtp_payload_format(0xFF),
    m_conn_endpoint_name(NULL),
    m_bandwidth(0),
    m_codec_name(NULL),
    m_rtp_timestamp_frequency(0),
    m_num_channels(1),
    m_multiplex_rtcp_with_rtp(false),
    m_control_path(NULL),
    m_play_start_time(0),
    m_play_end_time(0),
    m_abs_start_time(NULL),
    m_abs_end_time(NULL),
    m_source_filter_name(NULL),
    m_video_width(0), m_video_height(0),
    m_video_fps(0),
    m_rtp_socket(NULL), m_rtcp_socket(NULL),
    m_rtp_source(NULL),
    m_rtcp(NULL),
    m_session_id(NULL)
{
}

MediaSubsession::~MediaSubsession()
{
    SAFE_FREE(m_saved_sdp_lines);
    SAFE_FREE(m_medium_name);
    SAFE_FREE(m_protocol_name);
    SAFE_FREE(m_conn_endpoint_name);
    SAFE_FREE(m_codec_name);
    SAFE_FREE(m_control_path);
    SAFE_FREE(m_abs_start_time);
    SAFE_FREE(m_abs_end_time);
    SAFE_FREE(m_source_filter_name);
    SAFE_DELETE(m_rtp_socket);
    if (!m_multiplex_rtcp_with_rtp)
        SAFE_DELETE(m_rtcp_socket);
    SAFE_DELETE(m_rtp_source);
    SAFE_DELETE(m_rtcp);
    SAFE_FREE(m_session_id);
    FOR_MAP(m_attr_table, string, SDPAttribute *, it)
        SAFE_DELETE(MAP_VAL(it));
}

int MediaSubsession::parse_sdp_line_c(const char *sdp_line)
{
    char *conn_endpoint_name = parse_c_line(sdp_line);
    if (conn_endpoint_name) {
        SAFE_FREE(m_conn_endpoint_name);
        m_conn_endpoint_name = conn_endpoint_name;
        return 0;
    }
    return -1;
}

int MediaSubsession::parse_sdp_line_b(const char *sdp_line)
{
    return sscanf(sdp_line, "b=AS:%u", &m_bandwidth) == 1 ? 0 : -1;
}

int MediaSubsession::parse_sdp_attr_rtpmap(const char *sdp_line)
{
    int ret = -1;
    unsigned rtpmap_payload_format;
    char *codec_name = (char *) malloc(strlen(sdp_line) + 1);
    if (!codec_name) return -1;
    unsigned rtp_timestamp_frequency = 0;
    unsigned num_channels = 1;
    if (sscanf(sdp_line, "a=rtpmap: %u %[^/]/%u/%u",
                &rtpmap_payload_format, codec_name, &rtp_timestamp_frequency,
                &num_channels) == 4 ||
        sscanf(sdp_line, "a=rtpmap: %u %[^/]/%u",
                &rtpmap_payload_format, codec_name, &rtp_timestamp_frequency) == 3 ||
        sscanf(sdp_line, "a=rtpmap: %u %s",
                &rtpmap_payload_format, codec_name) == 2) {
        ret = 0;
        if (rtpmap_payload_format == m_rtp_payload_format) {
            for (char* p = codec_name; *p; ++p) *p = toupper(*p);
            SAFE_FREE(m_codec_name); m_codec_name = strdup(codec_name);
            m_rtp_timestamp_frequency = rtp_timestamp_frequency;
            m_num_channels = num_channels;
        }
    }
    SAFE_FREE(codec_name);
    return ret;
}

int MediaSubsession::parse_sdp_attr_rtcpmux(const char *sdp_line)
{
    if (strncmp(sdp_line, "a=rtcp-mux", 10) == 0) {
        m_multiplex_rtcp_with_rtp = true;
        return 0;
    }   
    return -1;
}

int MediaSubsession::parse_sdp_attr_control(const char *sdp_line)
{
    int ret = -1;
    char *control_path = (char *) malloc(strlen(sdp_line) + 1);
    if (sscanf(sdp_line, "a=control: %s", control_path) == 1) {
        ret = 0;
        SAFE_FREE(m_control_path); m_control_path = strdup(control_path);
    }
    SAFE_FREE(control_path);
    return ret;
}

static int parse_range_attr(const char *sdp_line,
        char *&abs_start_time, char *&abs_end_time)
{
    int len = strlen(sdp_line);
    char *as = (char *) malloc(len);
    char *ae = (char *) malloc(len);
    if (!as || !ae) return -1;
    int res = sscanf(sdp_line, "a=range: clock = %[^-\r\n]-%[^\r\n]", as, ae);
    if (res == 2) {
        abs_start_time = as;
        abs_end_time = ae;
    } else if (res == 1) {
        abs_start_time = as;
        SAFE_FREE(ae);
    } else {
        SAFE_FREE(as); SAFE_FREE(ae);
        return -1;
    }
    return 0;
}

int MediaSubsession::parse_sdp_attr_range(const char *sdp_line)
{
    int ret = -1;
    double play_start_time;
    double play_end_time;
    if (!parse_range_attr(sdp_line, play_start_time, play_end_time)) {
        ret = 0;
        if (play_start_time > m_play_start_time) {
            m_play_start_time = play_start_time;
            if (play_start_time > m_parent.play_start_time()) {
                m_parent.play_start_time() = play_start_time;
            }
        }
        if (play_end_time > m_play_end_time) {
            m_play_end_time = play_end_time;
            if (play_end_time > m_parent.play_end_time()) {
                m_parent.play_end_time() = play_end_time;
            }
        }
    } else if (!parse_range_attr(sdp_line, _abs_start_time(), _abs_end_time())) {
        ret = 0;
    }
    return ret;
}

int MediaSubsession::parse_sdp_attr_fmtp(const char *sdp_line)
{
    do {
        if (strncmp(sdp_line, "a=fmtp:", 7) != 0) break; sdp_line += 7;
        while (isdigit(*sdp_line)) ++sdp_line;
        ++sdp_line;

        unsigned const sdp_line_len = strlen(sdp_line);
        char* name_str = (char *) malloc(sdp_line_len+1);
        char* value_str = (char *) malloc(sdp_line_len+1);
        while (*sdp_line != '\0' && *sdp_line != '\r' && *sdp_line != '\n') {
            sdp_line = skip_blank((char *) sdp_line);
            int res = sscanf(sdp_line, "%[^=; \t\r\n]=%[^; \t\r\n]", name_str, value_str);
            if (res >= 1) {
                for (char* c = name_str; *c != '\0'; ++c) *c = tolower(*c);

                if (res == 1) {
                    set_attr(name_str);
                } else {
                    set_attr(name_str, value_str);
                }
            }

            while (*sdp_line != '\0' && *sdp_line != '\r' && *sdp_line != '\n' && *sdp_line != ';') ++sdp_line;
            while (*sdp_line == ';') ++sdp_line;
        }
        SAFE_FREE(name_str); SAFE_FREE(value_str);
        return 0;
    } while (0);
    return -1;
}

int MediaSubsession::parse_sdp_attr_source_filter(const char *sdp_line)
{
    return parse_source_filter_attr(sdp_line, m_source_filter_name);
}

int MediaSubsession::parse_sdp_attr_x_dimensions(const char *sdp_line)
{
    int ret = -1;
    int width, height;
    if (sscanf(sdp_line, "a=x-dimensions:%d,%d", &width, &height) == 2) {
        ret = 0;
        m_video_width = (unsigned short) width;
        m_video_height = (unsigned short) height;
    } 
    return ret;
}

int MediaSubsession::parse_sdp_attr_framerate(const char *sdp_line)
{
    int ret = -1;
    float frate;
    int rate;
    if (sscanf(sdp_line, "a=framerate: %f", &frate) == 1 ||
        sscanf(sdp_line, "a=framerate:%f", &frate) == 1) {
        ret = 0;
        m_video_fps = (unsigned)frate;
    } else if (sscanf(sdp_line, "a=x-framerate: %d", &rate) == 1) {
        ret = 0;
        m_video_fps = (unsigned)rate;
    }               
    return ret;
}

int MediaSubsession::initiate(const std::string &own_ip)
{
    if (m_rtp_source) return 0;

    do {
        if (!m_codec_name) {
            LOGE("Codec is unspecified");
            break;
        }

        TaskScheduler *scheduler = parent_session().rtsp_client()->scheduler();
        AddressPort ap;
        struct in_addr temp_addr;
        temp_addr.s_addr = connection_endpoint_address();

        if (m_client_port_num != 0 && is_multicast_address(temp_addr.s_addr)) {
            const bool protocol_is_rtp = strcmp(m_protocol_name, "RTP");
            if (protocol_is_rtp && !m_multiplex_rtcp_with_rtp)
                m_client_port_num = m_client_port_num&~1;

            ap.set_address_port(STR(own_ip), m_client_port_num);
            m_rtp_socket = new RtpInterface(scheduler,
                                            connection_endpoint_name(), server_port_num());
            if (m_rtp_socket->open(ap) < 0) {
                LOGE("Failed to create RTP socket");
                break;
            }

            if (protocol_is_rtp) {
                if (m_multiplex_rtcp_with_rtp)
                    m_rtcp_socket = m_rtp_socket;
                else {
                    const PortNumBits rtcp_port_num = m_client_port_num|1;
                    m_rtcp_socket = new RtpInterface(scheduler,
                                                     connection_endpoint_name(), server_port_num()+1);
                    ap.set_address_port(STR(own_ip), rtcp_port_num);
                    m_rtcp_socket->open(ap);
                }
            }
        } else {
            bool success = false;
            for ( ; ; ) {
                m_rtp_socket = new RtpInterface(scheduler,
                                                connection_endpoint_name(), server_port_num());
                ap.set_address_port(STR(own_ip), 0);
                if (m_rtp_socket->open(ap) < 0) {
                    LOGE("Unable to create RTP socket");
                    break;
                }
                m_client_port_num = ap.get_port();

                if (m_multiplex_rtcp_with_rtp) {
                    m_rtcp_socket = m_rtp_socket;
                    success = true;
                    break;
                }

                if ((m_client_port_num&1) != 0) {
                    SAFE_DELETE(m_rtp_socket);
                    continue;
                }

                PortNumBits rtcp_port_num = m_client_port_num|1;
                m_rtcp_socket = new RtpInterface(scheduler,
                                                 connection_endpoint_name(), server_port_num()+1);
                ap.set_address_port(STR(own_ip), rtcp_port_num);
                if (m_rtcp_socket->open(ap) < 0) {
                    SAFE_DELETE(m_rtcp_socket); SAFE_DELETE(m_rtp_socket);
                    continue;
                } else {
                    success = true;
                    break;
                }
            }
            if (!success) break;
        }

        unsigned rtp_buf_size = m_bandwidth * 25 / 2;
        if (rtp_buf_size < 50 * 1024)
            rtp_buf_size = 50 * 1024;
        m_rtp_socket->increate_receive_buffer_to(rtp_buf_size);

        if (create_source_object() < 0) break;

        if (!m_rtp_source) {
            LOGE("Failed to create read source");
            break;
        }

        if (m_rtcp_socket) {
            m_rtcp = new Rtcp(parent_session().rtsp_client()->scheduler(),
                              m_rtcp_socket, m_parent.CNAME(), this);
            if (!m_rtcp) {
                LOGE("Failed to create RTCP instance");
                break;
            }
        }

        // Also auto-enable rtp's data receiving
        if (m_rtp_source->start_receiving() < 0)
            break;
        return 0;
    } while (0);

    m_client_port_num = 0;
    return -1;
}

void MediaSubsession::set_attr(const char *name, const char *value, bool value_is_hexadecimal)
{
    AttrTable::iterator it = m_attr_table.find(name);
    if (it != m_attr_table.end()) {
        value_is_hexadecimal = MAP_VAL(it)->value_is_hexadecimal();
        m_attr_table.erase(it);
        SAFE_DELETE(MAP_VAL(it));
    }
    SDPAttribute *new_attr = new SDPAttribute(value, value_is_hexadecimal);
    m_attr_table.insert(pair<string, SDPAttribute *>(name, new_attr));
}

int MediaSubsession::attr_val_int(const char *attr_name)
{
    AttrTable::iterator it = m_attr_table.find(attr_name);
    if (it != m_attr_table.end())
        return MAP_VAL(it)->int_value();
    return 0;
}

const char *MediaSubsession::attr_val_str2lower(const char *attr_name)
{
    AttrTable::iterator it = m_attr_table.find(attr_name);
    if (it != m_attr_table.end())
        return MAP_VAL(it)->str_value_to_lower();
    return "";
}

const char *MediaSubsession::attr_val_str(const char *attr_name)
{
    AttrTable::iterator it = m_attr_table.find(attr_name);
    if (it != m_attr_table.end())
        return MAP_VAL(it)->str_value();
    return "";
}

NetAddressBits MediaSubsession::connection_endpoint_address()
{
    do {
        const char *endpoint_string = connection_endpoint_name();
        if (!endpoint_string)
            endpoint_string = parent_session().connection_endpoint_name();
        if (!endpoint_string) break;

        NetAddressList addresses(endpoint_string);
        if (!addresses.num_addresses()) break;

        return *(NetAddressBits *)(addresses.first_address()->data());
    } while (0);
    return 0;
}

void MediaSubsession::set_session_id(const char *session_id)
{
    SAFE_FREE(m_session_id);
    m_session_id = strdup(session_id);
}

int MediaSubsession::create_source_object()
{
    do {
        if (!strcmp(m_protocol_name, "UDP")) {
            LOGE("A UDP-packetized stream is not supported");
            break;
        } else {
            if (!strcmp(m_codec_name, "H264")) {
                m_rtp_source = new H264VideoRTPSource(
                        parent_session().rtsp_client()->scheduler(),
                        m_rtp_socket,
                        m_rtp_payload_format, m_rtp_timestamp_frequency,
                        attr_val_str("sprop-parameter-sets"),
                        parent_session().opaque());
            } else if (!strcmp(m_codec_name, "MPEG4-GENERIC")) {
                const char *fmtp_config = attr_val_str("config");
                if (!strlen(fmtp_config)) fmtp_config = attr_val_str("configuration");
                m_rtp_source = new MPEG4GenericRTPSource(
                        parent_session().rtsp_client()->scheduler(),
                        m_rtp_socket,
                        m_rtp_payload_format, m_rtp_timestamp_frequency,
                        m_medium_name, attr_val_str2lower("mode"),
                        attr_val_unsigned("sizelength"),
                        attr_val_unsigned("indexlength"),
                        attr_val_unsigned("indexdeltalength"),
                        fmtp_config,
                        parent_session().opaque());
            } else {
                LOGE("RTP payload format \"%s\" unknown or not supported",
                        m_codec_name);
                break;
            }
        }
        return 0;
    } while (0);
    return -1;
}

void MediaSubsession::close()
{
    TaskScheduler *scheduler = parent_session().rtsp_client()->scheduler();
    if (m_rtp_socket && m_rtp_socket->get_sockfd() != -1) {
        scheduler->turn_off_background_read_handling(m_rtp_socket->get_sockfd());
    }
    if (m_rtcp_socket && m_rtcp_socket->get_sockfd() != -1) {
        scheduler->turn_off_background_read_handling(m_rtcp_socket->get_sockfd());
    }
}

/////////////////////////////////////////////////////////////

static void remove_socket_descriptor(int sock_num)
{
    if (g_socket_table.find(sock_num) != g_socket_table.end()) {
        g_socket_table.erase(sock_num);
    }
}

SocketDescriptor::SocketDescriptor(TaskScheduler *scheduler, int socket_num) :
    m_scheduler(scheduler), m_our_socket_num(socket_num),
    m_read_error_occurred(false), m_delete_myself_next(false), m_are_in_read_handler_loop(false),
    m_tcp_reading_state(AWAITING_DOLLAR),
    m_next_tcp_read_size(0), m_next_tcp_read_stream_socket_num(-1), m_next_tcp_read_stream_channel_id(0xFF)
{
}

SocketDescriptor::~SocketDescriptor()
{
    m_scheduler->turn_off_background_read_handling(m_our_socket_num);
    remove_socket_descriptor(m_our_socket_num);

    FOR_MAP(m_sub_channel_map, unsigned char, void *, it) {
        unsigned char stream_channel_id = MAP_KEY(it);
        RtpInterface *rtp_interface = (RtpInterface *) MAP_VAL(it);

        rtp_interface->remove_stream_socket(m_our_socket_num, stream_channel_id);
    }
}

void SocketDescriptor::register_interface(unsigned char stream_channel_id, void *interface)
{
    bool is_first_registration = m_sub_channel_map.empty();
    m_sub_channel_map.insert(pair<unsigned char, void *>(stream_channel_id, interface));

    if (is_first_registration) {
        m_scheduler->turn_on_background_read_handling(m_our_socket_num,
                                                      (TaskScheduler::BackgroundHandlerProc *) &tcp_read_handler,
                                                      this);
    }
}

void SocketDescriptor::tcp_read_handler(SocketDescriptor *socket_descriptor, int mask)
{
    // Call the read handler until it returns false, with a limit to avoid starving other sockets
    unsigned count = 2000;
    socket_descriptor->m_are_in_read_handler_loop = true;
    while (!socket_descriptor->m_delete_myself_next &&
           socket_descriptor->tcp_read_handler1(mask) &&
           --count > 0) {
    }
    socket_descriptor->m_are_in_read_handler_loop = false;
    if (socket_descriptor->m_delete_myself_next) {
        delete socket_descriptor;
    }
}

bool SocketDescriptor::tcp_read_handler1(int mask)
{
    uint8_t c;
    if (m_tcp_reading_state != AWAITING_PACKET_DATA) {
        int result = recv(m_our_socket_num, &c, 1, MSG_NOSIGNAL);
        if (!result) {
            return false;
        } else if (result != 1) {
            m_read_error_occurred = true;
            m_delete_myself_next = true;
            return false;
        }
    }

    bool call_again = true;
    switch (m_tcp_reading_state) {
    case AWAITING_DOLLAR:
        if (c == '$') {
            m_tcp_reading_state = AWAITING_STREAM_CHANNEL_ID;
        } else {
            // This character is part of a RTSP request or command, ignore it
        }
        break;

    case AWAITING_STREAM_CHANNEL_ID:
        if (lookup_interface(c) != NULL) {
            m_stream_channel_id = c;
            m_tcp_reading_state = AWAITING_SIZE1;
        } else {
            // This wasn't a stream channel id that we expected.  We're (somehow) in a strange state.  Try to recover:
            LOGW("SocketDescriptor(socket %d)::tcp_read_handler1(): Saw nonexistent stream channel id: 0x%02x\n",
                 m_our_socket_num, c);
            m_tcp_reading_state = AWAITING_DOLLAR;
        }
        break;

    case AWAITING_SIZE1:
        // The byte that we read is the first (high) byte of the 16-bit RTP or RTCP packet 'size'.
        m_size_byte1 = c;
        m_tcp_reading_state = AWAITING_SIZE2;
        break;

    case AWAITING_SIZE2: {
        // The byte that we read is the second (low) byte of the 16-bit RTP or RTCP packet 'size'.
        unsigned short size = (m_size_byte1<<8)|c;

        // Record the information about the packet data that will be read next:
        RtpInterface *rtp_interface = (RtpInterface *) lookup_interface(m_stream_channel_id); 
        if (rtp_interface) {
            m_next_tcp_read_size = size;
            m_next_tcp_read_stream_socket_num = m_our_socket_num;
            m_next_tcp_read_stream_channel_id = m_stream_channel_id;
        }
        m_tcp_reading_state = AWAITING_PACKET_DATA;
        } break;

    case AWAITING_PACKET_DATA: {
        call_again = false;
        m_tcp_reading_state = AWAITING_DOLLAR;
        RtpInterface *rtp_interface = (RtpInterface *) lookup_interface(m_stream_channel_id); 
        if (rtp_interface) {
            if (m_next_tcp_read_size == 0) {
                // We've already read all the data for this packet
                break;
            }
            LOGW("No handler proc for \"rtp_interface\" for channel %d; need to skip %d remaining bytes\n",
                 m_our_socket_num, m_stream_channel_id, m_next_tcp_read_size);
            int result = recv(m_our_socket_num, &c, 1, MSG_NOSIGNAL);
            if (result < 0) { // error reading TCP socket, so we will no longer handle it
                m_read_error_occurred = true;
                m_delete_myself_next = true;
                return false;
            } else {
                m_tcp_reading_state = AWAITING_PACKET_DATA;
                if (result == 1) {
                    --m_next_tcp_read_size;
                    call_again = true;
                }
            }
        } else {
            LOGW("No \"rtp_interface\" for channel %d\n",
                 m_our_socket_num, m_stream_channel_id);
        }
        } break;
    }
    return call_again;
}

void *SocketDescriptor::lookup_interface(unsigned char stream_channel_id)
{
    if (m_sub_channel_map.find(stream_channel_id) != m_sub_channel_map.end())
        return m_sub_channel_map[stream_channel_id];
    return NULL;
}

void SocketDescriptor::deregister_interface(unsigned char stream_channel_id)
{
    if (m_sub_channel_map.find(stream_channel_id) != m_sub_channel_map.end()) {
        m_sub_channel_map.erase(stream_channel_id);
    }

    if (m_sub_channel_map.empty() ||
        stream_channel_id == 0xFF) {
        if (m_are_in_read_handler_loop) {
            m_delete_myself_next = true; // we can't delete ourself yet, but we'll do so from "tcp_read_handler()"
        } else {
            delete this;
        }
    }
}
    
/////////////////////////////////////////////////////////////

RtpInterface::RtpInterface(TaskScheduler *scheduler) :
    m_scheduler(scheduler)
{
}

RtpInterface::RtpInterface(TaskScheduler *scheduler, const AddressPort &remote) :
    Udp(remote), m_scheduler(scheduler)
{
}

RtpInterface::RtpInterface(TaskScheduler *scheduler, const char *ip, const uint16_t port) :
    Udp(ip, port), m_scheduler(scheduler)
{
}

RtpInterface::~RtpInterface()
{
    FOR_VECTOR_ITERATOR(TcpStreamRecord *, m_tcp_stream_record, it) {
        deregister_socket((*it)->m_stream_socket_num, (*it)->m_stream_channel_id);
        SAFE_DELETE(*it);
    }
    m_tcp_stream_record.clear();
}

void RtpInterface::set_stream_socket(int sockfd, unsigned char stream_channel_id)
{
    if (sockfd < 0) return;

    m_scheduler->turn_off_background_read_handling(get_sockfd());
    ::close(get_sockfd());
    set_sockfd(-1);

    FOR_VECTOR_CONST_ITERATOR(TcpStreamRecord *, m_tcp_stream_record, it) {
        if ((*it)->m_stream_socket_num == sockfd &&
            (*it)->m_stream_channel_id == stream_channel_id) {
            LOGW("sockfd(%d) with stream_channel_id(%d) already registered",
                 sockfd, stream_channel_id);
            return;
        }
    }

    TcpStreamRecord *record = new TcpStreamRecord(sockfd, stream_channel_id);
    m_tcp_stream_record.push_back(record);

    SocketDescriptor *socket_descriptor = NULL;
    if (g_socket_table.find(sockfd) == g_socket_table.end()) {
        socket_descriptor = new SocketDescriptor(m_scheduler, sockfd);
        g_socket_table.insert(pair<int, SocketDescriptor *>(sockfd, socket_descriptor));
    } else {
        socket_descriptor = g_socket_table[sockfd];
    }
    socket_descriptor->register_interface(stream_channel_id, this);
}

void RtpInterface::remove_stream_socket(int sock_num, unsigned char stream_channel_id)
{
    for (vector<TcpStreamRecord *>::iterator it = m_tcp_stream_record.begin();
         it != m_tcp_stream_record.end();
         ) {
        if ((*it)->m_stream_socket_num == sock_num &&
            (stream_channel_id == 0xFF || (*it)->m_stream_channel_id == stream_channel_id)) {
            SAFE_DELETE(*it);
            m_tcp_stream_record.erase(it++);

            deregister_socket(sock_num, stream_channel_id);

            if (stream_channel_id != 0xFF) return;
        } else {
            it++;
        }
    }
}

int RtpInterface::write(const uint8_t *buf, int size, struct sockaddr_in *remote)
{
    if (get_sockfd() != -1) {
        return Udp::write(buf, size, remote);
    }

    int ret = 0;
    FOR_VECTOR_CONST_ITERATOR(TcpStreamRecord *, m_tcp_stream_record, it) {
        if (send_rtp_or_rtcp_packet_over_tcp((uint8_t *) buf, size,
                                             (*it)->m_stream_socket_num, (*it)->m_stream_channel_id) < 0)
            ret = -1;
    }
    return ret;
} 

int RtpInterface::send_rtp_or_rtcp_packet_over_tcp(uint8_t *packet, unsigned packet_size,
                                                   int socket_num, unsigned char stream_channel_id)
{
#ifdef XDEBUG
    LOGD("%d bytes over channel %d (socket %d)",
         packet_size, stream_channel_id, socket_num);
#endif

    uint8_t framing_header[4];
    framing_header[0] = '$';
    framing_header[1] = stream_channel_id;
    framing_header[2] = (uint8_t) ((packet_size&0xFF00)>>8);
    framing_header[3] = (uint8_t) (packet_size&0xFF);

    if (!send_data_over_tcp(socket_num, framing_header, 4) &&
        !send_data_over_tcp(socket_num, packet, packet_size))
        return 0;

    return -1;
}

int RtpInterface::send_data_over_tcp(int socket_num,
                                     uint8_t *data, unsigned data_size)
{
    if (::send(socket_num, data, data_size, MSG_NOSIGNAL) < 0) {
        LOGE("Write data to network failed");
        remove_stream_socket(socket_num, 0xFF);
        return -1;
    }
    return 0;
}

/////////////////////////////////////////////////////////////

unsigned OutPacketBuffer::max_size = 150000;

OutPacketBuffer::OutPacketBuffer(unsigned preferred_packet_size, unsigned max_packet_size, unsigned max_buffer_size) :
    m_preferred(preferred_packet_size), m_max(max_packet_size),
    m_overflow_data_size(0) {
    if (max_buffer_size == 0) max_buffer_size = max_size;
    unsigned max_num_packets = (max_buffer_size + (max_packet_size - 1))/max_packet_size;
    m_limit = max_num_packets*max_packet_size;
    m_buf = new unsigned char[m_limit];
    reset_packet_start();
    reset_offset();
    reset_overflow_data();
}

OutPacketBuffer::~OutPacketBuffer()
{
    SAFE_DELETE_ARRAY(m_buf);
}

void OutPacketBuffer::enqueue(unsigned char const *from, unsigned num_bytes)
{
    if (num_bytes > total_bytes_available()) {
#ifdef XDEBUG
        LOGW("OutPacketBuffer::enqueue() warning: %d > %d",
             num_bytes, total_bytes_available());
#endif
        num_bytes = total_bytes_available();
    }

    if (cur_ptr() != from) memmove(cur_ptr(), from, num_bytes);
    increment(num_bytes);
}

void OutPacketBuffer::enqueue_word(uint32_t word)
{
    uint32_t n_word = EHTONL(word);
    enqueue((unsigned char *) &n_word, 4);
}

void OutPacketBuffer::insert(unsigned char const *from, unsigned num_bytes, unsigned to_position)
{
    unsigned real_to_position = m_packet_start + to_position;
    if (real_to_position + num_bytes > m_limit) {
        if (real_to_position > m_limit) {
            return;
        }
        num_bytes = m_limit - real_to_position;
    }

    memmove(&m_buf[real_to_position], from, num_bytes);
    if (to_position + num_bytes > m_cur_offset) {
        m_cur_offset = to_position + num_bytes;
    }
}

void OutPacketBuffer::insert_word(uint32_t word, unsigned to_position)
{
    uint32_t n_word = EHTONL(word);
    insert((unsigned char *) &n_word, 4, to_position);
}

void OutPacketBuffer::extract(unsigned char *to, unsigned num_bytes, unsigned from_position)
{
    unsigned real_from_position = m_packet_start + from_position;
    if (real_from_position + num_bytes > m_limit) {
        if (real_from_position > m_limit) {
            return;
        }
        num_bytes = m_limit - real_from_position;
    }

    memmove(to, &m_buf[real_from_position], num_bytes);
}

uint32_t OutPacketBuffer::extract_word(unsigned from_position)
{
    uint32_t n_word;
    extract((unsigned char*)&n_word, 4, from_position);
    return ENTOHL(n_word);
}

void OutPacketBuffer::skip_bytes(unsigned num_bytes)
{
    if (num_bytes > total_bytes_available()) {
        num_bytes = total_bytes_available();
    }

    increment(num_bytes);
}

void OutPacketBuffer::set_overflow_data(unsigned overflow_data_offset, unsigned overflow_data_size,
                                        struct timeval const &presentation_time,
                                        unsigned duration_in_microseconds)
{
    m_overflow_data_offset = overflow_data_offset;
    m_overflow_data_size = overflow_data_size;
    m_overflow_presentation_time = presentation_time;
    m_overflow_duration_in_microseconds = duration_in_microseconds;
}

void OutPacketBuffer::use_overflow_data()
{
    enqueue(&m_buf[m_packet_start + m_overflow_data_offset], m_overflow_data_size);
    m_cur_offset -= m_overflow_data_size;
    reset_overflow_data();
}

void OutPacketBuffer::adjust_packet_start(unsigned num_bytes)
{
    m_packet_start += num_bytes;
    if (m_overflow_data_offset >= num_bytes) {
        m_overflow_data_offset -= num_bytes;
    } else {
        reset_overflow_data();
    }
}

void OutPacketBuffer::reset_packet_start()
{
    if (m_overflow_data_size > 0) {
        m_overflow_data_offset += m_packet_start;
    }
    m_packet_start = 0;
}

/////////////////////////////////////////////////////////////

uint32_t random32()
{
    int r_1 = rand();
    uint32_t r16_1 = (uint32_t) (r_1&0x00FFFF00);

    int r_2 = rand();
    uint32_t r16_2 = (uint32_t) (r_2&0x00FFFF00);

    return (r16_1<<8) | (r16_2>>8);
}

TcpStreamRecord::TcpStreamRecord(int stream_socket_num, unsigned char stream_channel_id) :
    m_stream_socket_num(stream_socket_num), m_stream_channel_id(stream_channel_id)
{
}

TcpStreamRecord::~TcpStreamRecord()
{
}
    
/////////////////////////////////////////////////////////////

MultiFramedRTPSink::MultiFramedRTPSink(TaskScheduler *scheduler,
                                       RtpInterface *interface,
                                       uint8_t rtp_payload_type, uint32_t rtp_timestamp_frequency,
                                       const char *rtp_payload_format_name,
                                       unsigned num_channels) :
    m_scheduler(scheduler),
    m_queue_src(NULL),
    m_interface(interface),
    m_rtp_payload_type(rtp_payload_type),
    m_rtp_timestamp_frequency(rtp_timestamp_frequency),
    m_rtp_payload_format_name(strdup_(rtp_payload_format_name)),
    m_num_channels(num_channels),
    m_out_buf(NULL), m_cur_fragmentation_offset(0), m_previous_frame_ended_fragmentation(false),
    m_on_send_error_func(NULL), m_on_send_error_data(NULL),
    m_next_task(NULL)
{
    m_seq_num = rand();
    m_ssrc = random32();
    m_timestamp_base = random32();
    gettimeofday(&m_creation_time, NULL);
    reset_presentation_times();

    // Default max packet size (1500, minus allowance for IP, UDP, UMTP headers)
    // (Also, make it a multiple of 4 bytes, just in case that matters.)
    set_packet_sizes(1000, 1456);
}

MultiFramedRTPSink::~MultiFramedRTPSink()
{
    SAFE_DELETE(m_out_buf);
    free((char *) m_rtp_payload_format_name);
    if (m_next_task) {
        m_scheduler->unschedule_delayed_task(m_next_task);
    }
}

void MultiFramedRTPSink::set_packet_sizes(unsigned preferred_packet_size, unsigned max_packet_size)
{
    if (preferred_packet_size > max_packet_size ||
        preferred_packet_size == 0) {
        LOGW("preferred_packet_size=%u, max_packet_size=%u (ignored)",
             preferred_packet_size, max_packet_size);
        return;
    }

    SAFE_DELETE(m_out_buf);
    m_out_buf = new OutPacketBuffer(preferred_packet_size, max_packet_size);
    m_our_max_packet_size = max_packet_size;
}

void MultiFramedRTPSink::set_stream_socket(int sockfd, unsigned char stream_channel_id)
{
    m_interface->set_stream_socket(sockfd, stream_channel_id);
}

bool MultiFramedRTPSink::start_playing(Queue<Frame *> &queue_src,
                                       after_playing_func *after_func, void *after_client_data)
{
    if (m_queue_src) {
        LOGE("This sink is already beging played");
        return false;
    }

    m_queue_src = (Queue<Frame *> *) &queue_src;

    m_after_func = after_func;
    m_after_client_data = after_client_data;
    return continue_playing();
}

void MultiFramedRTPSink::stop_playing()
{
    m_queue_src = NULL;
    m_after_func = NULL;
}

void MultiFramedRTPSink::on_source_closure(void *client_data)
{
    MultiFramedRTPSink *sink = (MultiFramedRTPSink *) client_data;
    sink->on_source_closure();
}

void MultiFramedRTPSink::on_source_closure()
{
    m_queue_src = NULL;
    if (m_after_func) {
        (*m_after_func)(m_after_client_data);
    }
}

char const *MultiFramedRTPSink::sdp_media_type() const
{
    return "data";
}

char *MultiFramedRTPSink::rtpmap_line() const
{
    if (rtp_payload_type() >= 96) {
        string encoding_params_part;
        if (num_channels() != 1) {
            encoding_params_part = sprintf_("/%d", num_channels());
        } else {
            encoding_params_part = "";
        }
        char const * const rtpmap_fmt = "a=rtpmap:%d %s/%d%s"CRLF;
        unsigned rtpmap_fmt_size = strlen(rtpmap_fmt)
            + 3  + strlen(rtp_payload_format_name())
            + 20 + encoding_params_part.length();
        char *rtpmap_line = (char *) malloc(rtpmap_fmt_size);
        snprintf(rtpmap_line, rtpmap_fmt_size, rtpmap_fmt,
                rtp_payload_type(), rtp_payload_format_name(),
                rtp_timestamp_frequency(), STR(encoding_params_part));
        return rtpmap_line;
    } else {
        return strdup_("");
    }
}

char const *MultiFramedRTPSink::aux_sdp_line()
{
    return NULL;
}

bool MultiFramedRTPSink::continue_playing()
{
    build_and_send_packet(true);
    return true;
}

uint32_t MultiFramedRTPSink::convert_to_rtp_timestamp(struct timeval tv)
{
    uint32_t timestamp_increment = m_rtp_timestamp_frequency*tv.tv_sec;
    timestamp_increment += (uint32_t) (m_rtp_timestamp_frequency*(tv.tv_usec/1000000.0) + 0.5);

    uint32_t const rtp_timestamp = m_timestamp_base + timestamp_increment;

#ifdef XDEBUG
    LOGD("m_timestamp_base: 0x%08x, tv: %lu.%06ld\n\t=> RTP timestamp: 0x%08x",
         m_timestamp_base, tv.tv_sec, tv.tv_usec, rtp_timestamp);
#endif

    return rtp_timestamp;
}

void MultiFramedRTPSink::reset_presentation_times()
{
    m_initial_presentation_time.tv_sec = m_most_recent_presentation_time.tv_sec = 0;
    m_initial_presentation_time.tv_usec = m_most_recent_presentation_time.tv_usec = 0;
}

void MultiFramedRTPSink::build_and_send_packet(bool is_first_packet)
{
    m_is_first_packet = is_first_packet;

    // Set up the RTP header:
    unsigned rtp_hdr = 0x80000000; // version 2
    rtp_hdr |= (m_rtp_payload_type << 16); // PT
    rtp_hdr |= m_seq_num; // sequence number
    m_out_buf->enqueue_word(rtp_hdr);

    m_timestamp_position = m_out_buf->cur_packet_size(); // timestamp
    m_out_buf->skip_bytes(4); // leave a hole for the timestamp

    m_out_buf->enqueue_word(ssrc()); // synchronization source (SSRC) identifier

    // Allow for a special, payload-format-specific header following the
    // RTP header:
    m_special_header_position = m_out_buf->cur_packet_size();
    m_special_header_size = special_header_size();
    m_out_buf->skip_bytes(m_special_header_size);

    m_total_frame_specific_header_sizes = 0;
    m_num_frames_used_so_far = 0;
    pack_frame();
}

void MultiFramedRTPSink::do_special_frame_handling(unsigned fragmentation_offset,
                                                   unsigned char *frame_start,
                                                   unsigned num_bytes_in_frame,
                                                   struct timeval frame_presentation_time,
                                                   unsigned num_remaining_bytes)
{
    if (is_first_frame_in_packet()) {
        set_timestamp(frame_presentation_time);
    }
}

bool MultiFramedRTPSink::allow_fragmentation_after_start() const
{
    return false;
}

bool MultiFramedRTPSink::allow_other_frames_after_last_fragment() const
{
    return false;
}

bool MultiFramedRTPSink::frame_can_appear_after_packet_start(unsigned char const *frame_start,
                                                             unsigned num_bytes_in_frame) const
{
    return true;
}

unsigned MultiFramedRTPSink::special_header_size() const
{
    return 0;
}

unsigned MultiFramedRTPSink::frame_special_header_size() const
{
    return 0;
}

unsigned MultiFramedRTPSink::compute_overflow_for_new_frame(unsigned new_frame_size) const
{
    return m_out_buf->num_overflow_bytes(new_frame_size);
}

void MultiFramedRTPSink::set_marker_bit()
{
    unsigned rtp_hdr = m_out_buf->extract_word(0);
    rtp_hdr |= 0x00800000;
    m_out_buf->insert_word(rtp_hdr, 0);
}

void MultiFramedRTPSink::set_timestamp(struct timeval frame_presentation_time)
{
    m_current_timestamp = convert_to_rtp_timestamp(frame_presentation_time);

    m_out_buf->insert_word(m_current_timestamp, m_timestamp_position);
}

void MultiFramedRTPSink::set_special_header_word(unsigned word, unsigned word_position)
{
    m_out_buf->insert_word(word, m_special_header_position + 4*word_position);
}

void MultiFramedRTPSink::set_special_header_bytes(unsigned char const *bytes, unsigned num_bytes,
                                                  unsigned byte_position)
{
    m_out_buf->insert(bytes, num_bytes, m_special_header_position + byte_position);
}

void MultiFramedRTPSink::set_frame_specific_header_word(unsigned word, unsigned word_position)
{
    m_out_buf->insert_word(word, m_cur_frame_specific_header_position + 4*word_position);
}

void MultiFramedRTPSink::set_frame_specific_header_bytes(unsigned char const *bytes, unsigned num_bytes,
                                                         unsigned byte_position)
{
    m_out_buf->insert(bytes, num_bytes, m_cur_frame_specific_header_position + byte_position);
}

void MultiFramedRTPSink::set_frame_padding(unsigned num_padding_bytes)
{
    if (num_padding_bytes > 0) {
        unsigned char padding_buffer[255];
        memset(padding_buffer, 0, num_padding_bytes);
        padding_buffer[num_padding_bytes-1] = num_padding_bytes;
        m_out_buf->enqueue(padding_buffer, num_padding_bytes);

        unsigned rtp_hdr = m_out_buf->extract_word(0);
        rtp_hdr |= 0x20000000;
        m_out_buf->insert_word(rtp_hdr, 0);
    }
}

void MultiFramedRTPSink::pack_frame()
{
    // First, see if we have an overflow frame that was too big for the last pkt
    if (m_out_buf->have_overflow_data()) {
        // Use this frame before reading a new one from the source
        unsigned frame_size = m_out_buf->overflow_data_size();
        struct timeval presentation_time = m_out_buf->overflow_presentation_time();
        unsigned duration_in_microseconds = m_out_buf->overflow_duration_in_microseconds();
        m_out_buf->use_overflow_data();

        after_getting_frame1(frame_size, 0, presentation_time, duration_in_microseconds);
    } else {
        // Normal case: we need to read a new frame from the source
        if (!m_queue_src) return;

        m_cur_frame_specific_header_position = m_out_buf->cur_packet_size();
        m_cur_frame_specific_header_size = frame_special_header_size();
        m_out_buf->skip_bytes(m_cur_frame_specific_header_size);
        m_total_frame_specific_header_sizes += m_cur_frame_specific_header_size;

        if (!strcmp(sdp_media_type(), "video")) {
            H264Fragmenter *h264_fragmenter = (H264Fragmenter *) m_queue_src;
            h264_fragmenter->get_next_frame(m_out_buf->cur_ptr(), m_out_buf->total_bytes_available(),
                                            after_getting_frame, this);
        } else {
            // Audio stuff
        }
    }
}

void MultiFramedRTPSink::send_packet_if_necessary()
{
    if (m_num_frames_used_so_far > 0) {
        // Send the packet:
        if (m_interface->write(m_out_buf->packet(), m_out_buf->cur_packet_size()) < 0) {
            if (m_on_send_error_func) {
                (*m_on_send_error_func)(m_on_send_error_data);
            }
        }
        ++m_seq_num; // for next time
    }

    if (m_out_buf->have_overflow_data() &&
        m_out_buf->total_bytes_available() > m_out_buf->total_buffer_size()/2) {
        // Efficiency hack: Reset the packet start pointer to just in front of
        // the overflow data (allowing for the RTP header and special headers),
        // so that we probably don't have to "memmove" the overflow data
        // into place when building the next packet:
        unsigned new_packet_start = m_out_buf->cur_packet_size() -
                                    (rtp_header_size + m_special_header_size + frame_special_header_size());
        m_out_buf->adjust_packet_start(new_packet_start);
    } else {
        // Normal case: Reset the packet start pointer back to the start:
        m_out_buf->reset_packet_start();
    }
    m_out_buf->reset_offset();
    m_num_frames_used_so_far = 0;

    struct timeval now;
    gettimeofday(&now, NULL);
    int secs_diff = m_next_send_time.tv_sec - now.tv_sec;
    int64_t usecs_to_go = secs_diff*1000000 + (m_next_send_time.tv_usec - now.tv_usec);
    if (usecs_to_go < 0 || secs_diff < 0) {
        usecs_to_go = 0;
    }
    if (m_next_task) {
        m_scheduler->unschedule_delayed_task(m_next_task);
    }
    m_next_task = m_scheduler->schedule_delayed_task(usecs_to_go, send_next, this);
}

void MultiFramedRTPSink::send_next(void *first_arg)
{
    MultiFramedRTPSink *sink = (MultiFramedRTPSink *) first_arg;
    sink->build_and_send_packet(false);
}

void MultiFramedRTPSink::after_getting_frame(void *client_data,
                                             unsigned num_bytes_read, unsigned num_truncated_bytes,
                                             struct timeval presentation_time, unsigned duration_in_microseconds)
{
    MultiFramedRTPSink *sink = (MultiFramedRTPSink *) client_data;
    sink->after_getting_frame1(num_bytes_read, num_truncated_bytes,
                               presentation_time, duration_in_microseconds);
}

void MultiFramedRTPSink::after_getting_frame1(unsigned frame_size, unsigned num_truncated_bytes,
                                              struct timeval presentation_time, unsigned duration_in_microseconds)
{
    if (m_is_first_packet) {
        // Record the fact that we're are starting to play now:
        gettimeofday(&m_next_send_time, NULL);
    }

    m_most_recent_presentation_time = presentation_time;
    if (m_initial_presentation_time.tv_sec == 0 && m_initial_presentation_time.tv_usec == 0) {
        m_initial_presentation_time = presentation_time;
    }

    if (num_truncated_bytes > 0) {
        unsigned const buffer_size = m_out_buf->total_bytes_available();
        LOGW("The input frame data was too large for our buffer size (%u). %u bytes of trailing data was dropped!",
             buffer_size, num_truncated_bytes);
    }
    unsigned cur_fragmentation_offset = m_cur_fragmentation_offset;
    unsigned num_frame_bytes_to_use = frame_size;
    unsigned overflow_bytes = 0;

    // If we have already packed one or more frames into this packet,
    // check whether this new frame is eligible to be packed after them.
    // (This is indenpendent of whether the packet has enough room for this
    // new frame; that check comes later)
    if (m_num_frames_used_so_far > 0) {
        if ((m_previous_frame_ended_fragmentation && !allow_other_frames_after_last_fragment()) ||
            !frame_can_appear_after_packet_start(m_out_buf->cur_ptr(), frame_size)) {
            // Save away this frame for next time:
            num_frame_bytes_to_use = 0;
            m_out_buf->set_overflow_data(m_out_buf->cur_packet_size(), frame_size,
                                         presentation_time, duration_in_microseconds);
        }
    }
    m_previous_frame_ended_fragmentation = false;

    if (num_frame_bytes_to_use > 0) {
        // Check whether this frame overflows the packet
        if (m_out_buf->would_overflow(frame_size)) {
            // Don't use this frame now; instead, save it as overflow data, and
            // send it in the next packet instead. However, if the frame is too
            // big to fit in a packet by itself, then we need to fragment it (and
            // use some of it in this packet, if the payload format permits this.)
            if (is_too_big_for_a_packet(frame_size) &&
                (m_num_frames_used_so_far == 0 || allow_fragmentation_after_start())) {
                // We need to fragment this frame, and use some of it now:
                overflow_bytes = compute_overflow_for_new_frame(frame_size);
                num_frame_bytes_to_use -= overflow_bytes;
                m_cur_fragmentation_offset += num_frame_bytes_to_use;
            } else {
                // We don't use any of this frame:
                overflow_bytes = frame_size;
                num_frame_bytes_to_use = 0;
            }
            m_out_buf->set_overflow_data(m_out_buf->cur_packet_size() + num_frame_bytes_to_use,
                                         overflow_bytes, presentation_time, duration_in_microseconds);
        } else if (m_cur_fragmentation_offset > 0) {
            // This is the last fragment of a frame that was fragmented over
            // more than one packet. Do any special handing for this case:
            m_cur_fragmentation_offset = 0;
            m_previous_frame_ended_fragmentation = true;
        }
    }

    if (num_frame_bytes_to_use == 0 && frame_size > 0) {
        // Send our packet now, because we have filled it up:
        send_packet_if_necessary();
    } else {
        // Use this frame in our outgoing packet:
        unsigned char *frame_start = m_out_buf->cur_ptr();
        m_out_buf->increment(num_frame_bytes_to_use);

        // Here's where any payload format specific processing gets done:
        do_special_frame_handling(cur_fragmentation_offset, frame_start,
                                  num_frame_bytes_to_use,
                                  presentation_time,
                                  overflow_bytes);

        ++m_num_frames_used_so_far;

        // Update the time at which the next packet should be sent, based
        // on the duration of the frame that we just packed into it.
        // However, if this frame has overflow data remaining, then don't
        // count its duratin yet.
        if (overflow_bytes == 0) {
            m_next_send_time.tv_usec += duration_in_microseconds;
            m_next_send_time.tv_sec += m_next_send_time.tv_usec/1000000;
            m_next_send_time.tv_usec %= 1000000;
        }

        // Send our packet now if
        // (i) it's already at our preferred size or
        // (ii) (heuristic) another frame of the same size as the one we just
        //      read would overflow the packet, or
        // (iii) it contains the last fragment of a fragmented frame, and we 
        //      don't allow anything else to follow this or
        // (iv) one frame per packet is allowed:
        if (m_out_buf->is_preferred_size() ||
            m_out_buf->would_overflow(num_frame_bytes_to_use) ||
            (m_previous_frame_ended_fragmentation && !allow_other_frames_after_last_fragment()) ||
            !frame_can_appear_after_packet_start(m_out_buf->cur_ptr() - frame_size, frame_size)) {
            send_packet_if_necessary();
        } else {
            pack_frame();
        }
    }
}

bool MultiFramedRTPSink::is_too_big_for_a_packet(unsigned num_bytes) const
{
    num_bytes += rtp_header_size + special_header_size() + frame_special_header_size();
    return m_out_buf->is_too_big_for_a_packet(num_bytes);
}

/////////////////////////////////////////////////////////////

H264Fragmenter::H264Fragmenter(xutil::Queue<xmedia::Frame *> * queue_src,
                               unsigned input_buffer_max, unsigned max_output_packet_size) :
    m_queue_src(queue_src),
    m_input_buffer_size(input_buffer_max + 1), m_max_output_packet_size(max_output_packet_size),
    m_num_valid_data_bytes(1), m_cur_data_offset(1),
    m_last_fragment_completed_nal_unit(true),
    m_duration_in_microseconds(0),
    m_nalu_index_in_parser(0),
    m_frame(NULL),
    m_prev_ts(-1)
{
    m_presentation_time.tv_sec = m_presentation_time.tv_usec = 0;

    m_input_buffer = new unsigned char[m_input_buffer_size];
}

H264Fragmenter::~H264Fragmenter()
{
    SAFE_DELETE(m_frame);
    SAFE_DELETE_ARRAY(m_input_buffer);
}

void H264Fragmenter::get_next_frame(unsigned char *to, unsigned max_size,
                                    after_getting_func *func, void *data)
{
    m_to = to;
    m_max_size = max_size; // max buffer size to store the read data
    m_after_getting_func = func; // callback when frame read
    m_after_getting_client_data = data;

    if (m_num_valid_data_bytes == 1) {
        // We have no NAL unit data currently in the buffer. Read a new one
        if (m_nalu_index_in_parser == 0) {
            SAFE_DELETE(m_frame);

            if (m_queue_src->pop(m_frame) < 0) {
                // pop a frame from input queue
                return;
            }

            // Split the frame into nalus
            m_vparser.process(m_frame->m_dat, m_frame->m_dat_len);
        }

        unsigned frame_size = m_vparser.get_nalu_length(m_nalu_index_in_parser);
        unsigned num_truncated_bytes = 0;
        if (frame_size > m_input_buffer_size - 1) {
            LOGW("frame_size=%u, m_input_buffer_size-1=%u",
                 frame_size, m_input_buffer_size - 1);
            num_truncated_bytes = frame_size - (m_input_buffer_size - 1);
            frame_size = m_input_buffer_size - 1;
        }
        memcpy(&m_input_buffer[1], m_vparser.get_nalu_data(m_nalu_index_in_parser), frame_size);

        struct timeval presentation_time;
        presentation_time.tv_sec = m_frame->m_ts/1000;
        presentation_time.tv_usec = (m_frame->m_ts%1000)*1000;

        if (++m_nalu_index_in_parser >= m_vparser.get_nalu_num()) {
            // this frame is done
            m_nalu_index_in_parser = 0;
            if (m_prev_ts == -1) {
                m_prev_ts = m_frame->m_ts;
            }
            m_duration_in_microseconds = (m_frame->m_ts - m_prev_ts) * 1000;
            m_prev_ts = m_frame->m_ts;
        }

        after_getting_frame1(frame_size, num_truncated_bytes,
                             presentation_time, m_duration_in_microseconds);
    } else {
        // We have NAL unit data in the buffer. There are three cases to consider:
        // 1. There is a new NAL unit in the buffer, and it's small enough to deliver
        //    to the RTP sink.
        // 2. There is a new NAL unit in the buffer, but it's too large to deliver to
        //    the RTP sink in its entirety. Deliver the first fragment of this data,
        //    as a FU packet, with one extra preceding header byte (for the "FU header").
        // 3. There is a NAL unit in the buffer, and we've already deliverd some
        //    fragment(s) of this. Deliver the next fragment of this data,
        //    as a FU packet, with two (H.264) extra preceding header bytes
        //    (for the "NAL header" and the "FU header").
        if (m_max_size < m_max_output_packet_size) { // shouldn't happen
            LOGW("m_max_size(%u) is smaller than expected",
                 m_max_size);
        } else {
            m_max_size = m_max_output_packet_size;
        }

        m_last_fragment_completed_nal_unit = true; // by default
        if (m_cur_data_offset == 1) { // case 1 or 2
            if (m_num_valid_data_bytes - 1 <= m_max_size) { // case 1
                memmove(m_to, &m_input_buffer[1], m_num_valid_data_bytes - 1);
                m_frame_size = m_num_valid_data_bytes - 1;
                m_cur_data_offset = m_num_valid_data_bytes;
            } else { // case 2
                // We need to send the NAL unit data as a FU packets. Deliver the first
                // packet now. Note that we add "NAL header" and "FU header" bytes to the front
                // of the packet (overwriting the existing "NAL header")
                m_input_buffer[0] = (m_input_buffer[1] & 0xE0) | 28; // FU indicator
                m_input_buffer[1] = 0x80 | (m_input_buffer[1] & 0x1F); //  FU header (with S bit)
                memmove(m_to, m_input_buffer, m_max_size);
                m_frame_size = m_max_size;
                m_cur_data_offset += m_max_size - 1;
                m_last_fragment_completed_nal_unit = false;
            }
        } else { // case 3
            // We are sending this NAL unit data as FU packets. We've already sent the
            // first packet (fragment). Now, send the next fragment. Note that we add 
            // "NAL header" and "FU header" bytes to the front. (We reuse these bytes that
            // we already sent for the first fragment, but clear the S bit, and add the E
            // bit if this is the last fragment.)
            unsigned num_extra_header_bytes = 2;
            m_input_buffer[m_cur_data_offset - 2] = m_input_buffer[0]; // FU indicator
            m_input_buffer[m_cur_data_offset - 1] = m_input_buffer[1]&~0x80; // FU header (no S bit)
            unsigned num_bytes_to_send = num_extra_header_bytes + (m_num_valid_data_bytes - m_cur_data_offset);
            if (num_bytes_to_send > m_max_size) {
                // We can't send all of the remaining data this time:
                num_bytes_to_send = m_max_size;
                m_last_fragment_completed_nal_unit = false;
            } else {
                // This is the last fragment:
                m_input_buffer[m_cur_data_offset - 1] |= 0x40; // set the E bit in the FU header
            }
            memmove(m_to, &m_input_buffer[m_cur_data_offset - num_extra_header_bytes], num_bytes_to_send);
            m_frame_size = num_bytes_to_send;
            m_cur_data_offset += num_bytes_to_send - num_extra_header_bytes;
        }

        if (m_cur_data_offset >= m_num_valid_data_bytes) {
            m_num_valid_data_bytes = m_cur_data_offset = 1;
        }

        m_after_getting_func(m_after_getting_client_data,
                             m_frame_size, 0,
                             m_presentation_time, m_duration_in_microseconds);
        m_duration_in_microseconds = 0;
    }
}

bool H264Fragmenter::picture_end_marker() const
{
    return m_nalu_index_in_parser == 0;
}

void H264Fragmenter::after_getting_frame1(unsigned frame_size, unsigned num_truncated_bytes,
                                          struct timeval presentation_time, unsigned duration_in_microseconds)
{
    m_num_valid_data_bytes += frame_size;
    UNUSED(num_truncated_bytes);
    m_presentation_time = presentation_time;
    m_duration_in_microseconds = duration_in_microseconds;

    get_next_frame(m_to, m_max_size,
                   m_after_getting_func, m_after_getting_client_data);
}

H264VideoRTPSink::H264VideoRTPSink(TaskScheduler *scheduler,
                                   RtpInterface *interface, unsigned char rtp_payload_format,
                                   uint8_t const *sps, unsigned sps_size,
                                   uint8_t const *pps, unsigned pps_size) :
    MultiFramedRTPSink(scheduler, interface, rtp_payload_format, 90000, "H264"),
    m_our_fragmenter(NULL), m_fmtp_sdp_line(NULL)
{
    if (sps) {
        m_sps_size = sps_size;
        m_sps = new uint8_t[m_sps_size];
        memmove(m_sps, sps, m_sps_size);
    } else {
        m_sps = NULL;
        m_sps_size = 0;
    }
    if (pps) {
        m_pps_size = pps_size;
        m_pps = new uint8_t[m_pps_size];
        memmove(m_pps, pps, m_pps_size);
    } else {
        m_pps = NULL;
        m_pps_size = 0;
    }
}

H264VideoRTPSink::~H264VideoRTPSink()
{
    SAFE_FREE(m_fmtp_sdp_line);
    SAFE_DELETE_ARRAY(m_sps); SAFE_DELETE_ARRAY(m_pps);
    SAFE_DELETE(m_our_fragmenter);
}

char const *H264VideoRTPSink::sdp_media_type() const
{
    return "video";
}

char const *H264VideoRTPSink::aux_sdp_line()
{
    if (!m_sps || !m_pps) {
        LOGW("Unknown sps and/or pps in H264VideoRTPSink");
        return NULL;
    }

    uint32_t profile_level_id = (m_sps[1]<<16) | (m_sps[2]<<8) | m_sps[3];
    char *sps_base64 = base64_encode((char *) m_sps, m_sps_size);
    char *pps_base64 = base64_encode((char *) m_pps, m_pps_size);

    SAFE_FREE(m_fmtp_sdp_line);
    m_fmtp_sdp_line = strdup_(STR(sprintf_(
                    "a=fmtp:%d packetization-mode=1;profile-level-id=%06X;sprop-parameter-sets=%s,%s"CRLF,
                    rtp_payload_type(), profile_level_id, sps_base64, pps_base64)));

    SAFE_FREE(sps_base64);
    SAFE_FREE(pps_base64);

    return m_fmtp_sdp_line;
}

bool H264VideoRTPSink::continue_playing()
{
    if (!m_our_fragmenter) {
        m_our_fragmenter = new H264Fragmenter(m_queue_src,
                                              OutPacketBuffer::max_size, our_max_packet_size() - rtp_header_size);
    }
    m_queue_src = (xutil::Queue<xmedia::Frame *> *) m_our_fragmenter;

    return MultiFramedRTPSink::continue_playing();
}

void H264VideoRTPSink::do_special_frame_handling(unsigned fragmentation_offset,
                                                 unsigned char *frame_start,
                                                 unsigned num_bytes_in_frame,
                                                 struct timeval frame_presentation_time,
                                                 unsigned num_remaining_bytes)
{
    // Set the RTP 'M' (marker) bit if
    // 1/ The most recently delivered fragment was the end of (or the only fragment of) an NAL unit, and
    // 2/ This NAL unit was the last NAL unit of an 'access unit' (i.e. video frame).
    if (m_our_fragmenter) {
        if (m_our_fragmenter->last_fragment_completed_nal_unit() &&
            m_our_fragmenter->picture_end_marker()) {
            set_marker_bit();
        }
    }

    set_timestamp(frame_presentation_time);
}

bool H264VideoRTPSink::frame_can_appear_after_packet_start(unsigned char const *frame_start,
                                                           unsigned num_bytes_in_frame) const
{
    return false;
}

/////////////////////////////////////////////////////////////

MPEG4GenericRTPSink::MPEG4GenericRTPSink(TaskScheduler *scheduler,
                                         RtpInterface *interface, unsigned char rtp_payload_format,
                                         uint32_t rtp_timestamp_frequency,
                                         char const *sdp_media_type_string,
                                         char const *mpeg4_mode, char const *config_string,
                                         unsigned num_channels) :
    MultiFramedRTPSink(scheduler, interface, rtp_payload_format,
                       rtp_timestamp_frequency, "MPEG4-GENERIC", num_channels),
    m_sdp_media_type_string(strdup_(sdp_media_type_string)),
    m_mpeg4_mode(strdup_(mpeg4_mode)),
    m_config_string(strdup_(config_string))
{
    m_fmtp_sdp_line = strdup_(STR(sprintf_(
                    "a=fmtp:%d streamtype=5;profile-level-id=1;mode=%s;sizelength=13;indexlength=3;indexdeltalength=3;config=%s"CRLF,
                    rtp_payload_type(), m_mpeg4_mode, m_config_string)));
}

MPEG4GenericRTPSink::~MPEG4GenericRTPSink()
{
    free((char *) m_sdp_media_type_string);
    free((char *) m_mpeg4_mode);
    free((char *) m_config_string);
    SAFE_FREE(m_fmtp_sdp_line);
}

char const *MPEG4GenericRTPSink::sdp_media_type() const
{
    return m_sdp_media_type_string;
}

char const *MPEG4GenericRTPSink::aux_sdp_line()
{
    return m_fmtp_sdp_line;
}

}
