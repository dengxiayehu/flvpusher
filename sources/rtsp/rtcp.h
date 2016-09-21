#ifndef _RTCP_H_
#define _RTCP_H_

#define EVENT_REPORT    1
#define EVENT_SDES      2

#include "rtsp_common.h"

namespace flvpusher {

class TaskScheduler;
class RtpInterface;
class MediaSubsession;
class MultiFramedRTPSource;
class MultiFramedRTPSink;

class Rtcp {
public:
  Rtcp(TaskScheduler *scheduler, RtpInterface *interface, const char *cname, MediaSubsession *subsess);
  virtual ~Rtcp();

  void set_stream_socket(int sockfd, unsigned char stream_channel_id);

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
  RtpInterface *m_interface;
  MediaSubsession *m_subsess;
  RtcpSDES m_peer_sdes;
  enum {RTCP_RX_SDES_BUF_LEN = 64};
  char m_peer_sdes_buf[RTCP_RX_SDES_BUF_LEN];
  int m_type_of_event;
  TaskToken m_on_expire_task;
  MultiFramedRTPSink *m_sink;
  MultiFramedRTPSource *m_source;
  TaskScheduler *m_scheduler;
};

}

#endif /* end of _RTCP_H_ */
