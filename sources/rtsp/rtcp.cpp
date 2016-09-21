#include <xutil/amf.h>
#include <xlog.h>

#include "rtcp.h"
#include "rtp_interface.h"
#include "media_session.h"
#include "media_subsession.h"

using namespace amf;

namespace flvpusher {

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

  common->length = EHTONS((p-psave+4+4+3)/4-1); // Length

  if (m_interface->write((uint8_t *) m_peer_sdes_buf, (ENTOHS(common->length)+1)*4) < 0) {
    LOGE("Send RTCP SDES to server failed");
    // Fall through
  }
}

}
