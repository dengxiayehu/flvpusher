#include <xlog.h>
#include <memory>
#include <xuri.h>

#include "rtsp_sink.h"
#include "rtsp_client.h"
#include "rtp_interface.h"
#include "h264_video_rtp_sink.h"
#include "mpeg4_generic_rtp_sink.h"
#include "rtcp.h"
#include "common/raw_parser.h"
#include "common/config.h"

using namespace xutil;
using namespace xmedia;

namespace flvpusher {
    
class SubstreamDescriptor {
public:
  SubstreamDescriptor(MultiFramedRTPSink *rtp_sink, Rtcp *rtcp, unsigned track_id);
  ~SubstreamDescriptor();

  MultiFramedRTPSink *rtp_sink() const { return m_rtp_sink; }
  Rtcp *rtcp() const { return m_rtcp; }
  char const *sdp_lines() const { return m_sdp_lines; }

private:
  MultiFramedRTPSink *m_rtp_sink;
  Rtcp *m_rtcp;
  char *m_sdp_lines;
};

SubstreamDescriptor::SubstreamDescriptor(MultiFramedRTPSink *rtp_sink, Rtcp *rtcp, unsigned track_id) :
  m_rtp_sink(rtp_sink), m_rtcp(rtcp)
{
  char *rtpmap_line = m_rtp_sink->rtpmap_line();
  char const *aux_sdp_line = m_rtp_sink->aux_sdp_line();
  if (!aux_sdp_line) aux_sdp_line = "";

  m_sdp_lines = strdup_(STR(sprintf_("m=%s 0 RTP/AVP %u"CRLF
                        "%s"
                        "%s"
                        "a=control:trackID=%u"CRLF,
                        m_rtp_sink->sdp_media_type(), m_rtp_sink->rtp_payload_type(),
                        rtpmap_line,
                        aux_sdp_line,
                        track_id)));
  SAFE_FREE(rtpmap_line);
}

SubstreamDescriptor::~SubstreamDescriptor()
{
  SAFE_FREE(m_sdp_lines);
}

/////////////////////////////////////////////////////////////

RtspSink::RtspSink(const std::string &flvpath) :
  MediaSink(flvpath),
  m_proc_thrd(NULL),
  m_substream_sdp_sizes(0),
  m_last_track_id(0),
  m_video(new MediaAggregation), m_audio(new MediaAggregation),
  m_send_error(false),
  m_start_sink(false),
  m_first_key_frame_timestamp(0)
{
  m_client = new RtspClient(NULL);
}

RtspSink::~RtspSink()
{
  disconnect();

  JOIN_DELETE_THREAD(m_proc_thrd);

  FOR_VECTOR_ITERATOR(SubstreamDescriptor *, m_substream_descriptors, it) {
    SAFE_DELETE(*it);
  }

  SAFE_DELETE(m_video);
  SAFE_DELETE(m_audio);
  SAFE_DELETE(m_client);
}

MediaSink::Type RtspSink::type() const
{
  return RTSP_SINK;
}

std::string RtspSink::type_str() const
{
  return "rtsp";
}

int RtspSink::connect(const std::string &liveurl)
{
  m_our_ap = AddressPort(our_ip(), 0);
  if (m_client->open(liveurl, m_our_ap) < 0)
    return -1;

  if (m_client->request_options() < 0) {
    LOGE("Failed to send OPTIONS command");
    return -1;
  }

  m_liveurl = liveurl;
  m_proc_thrd = CREATE_THREAD_ROUTINE(proc_routine, NULL, false);
  return 0;
}

void *RtspSink::proc_routine(void *arg)
{
  m_client->loop(interrupt_variable());
  return (void *) NULL;
}

int RtspSink::disconnect()
{
  set_interrupt(true);

  if (m_video->sink)
    m_video->sink->stop_playing();
  if (m_audio->sink)
    m_audio->sink->stop_playing();

  RtspClient::shutdown_stream(m_client);
  return 0;
}

int RtspSink::send_video(int32_t timestamp, byte *dat, uint32_t length,
                         uint32_t composition_time)
{
  Frame *f = new Frame;
  f->make_frame(timestamp, dat, length, false);
  m_video->queue.push(f);

  AutoLock l(m_mutex);

  if (m_send_error) return -1;

  if (!m_video->sink) {
    VideoRawParser vparser;
    if (!vparser.process(dat, length) &&
        vparser.is_key_frame() &&
        vparser.get_sps_length() && vparser.get_pps_length()) {
      m_first_key_frame_timestamp = timestamp;

      TaskScheduler *scheduler = m_client->scheduler();
      m_video->rtp_socket = new RtpInterface(scheduler);
      m_video->sink = new H264VideoRTPSink(scheduler, m_video->rtp_socket, 96,
                                           vparser.get_sps(), vparser.get_sps_length(),
                                           vparser.get_pps(), vparser.get_pps_length());
      m_video->rtcp_socket = new RtpInterface(scheduler);
      m_video->rtcp = new Rtcp(scheduler, m_video->rtcp_socket, NULL, NULL);
      add_stream(m_video->sink, m_video->rtcp);
    }
  }

  if (!m_start_sink &&
      (timestamp - m_first_key_frame_timestamp) > RTSP_SINK_BUFFERING_TIME_AFTER_KEY_FRAME &&
      m_video->sink) {
    m_start_sink = true;

    if (set_destination_and_play() < 0) {
      LOGE("set_destination_and_play() failed");
      return -1;
    }
  }

  return 0;
}

int RtspSink::send_audio(int32_t timestamp, byte *dat, uint32_t length)
{
  Frame *f = new Frame;
  f->make_frame(timestamp, dat, length, false);
  m_audio->queue.push(f);

  AutoLock l(m_mutex);

  if (m_send_error) return -1;

  if (!m_audio->sink) {
    AudioRawParser aparser;
    if (!aparser.process(dat, length)) {
      TaskScheduler *scheduler = m_client->scheduler();
      byte asc[2];
      memcpy(asc, aparser.get_asc(), 2);
      uint8_t profile, sample_rate_idx, channel;
      parse_asc(asc, 2, profile, sample_rate_idx, channel);
      m_audio->rtp_socket = new RtpInterface(scheduler);
      m_audio->sink = new MPEG4GenericRTPSink(scheduler, m_audio->rtp_socket, 97,
                                              atoi(samplerate_idx_to_str(sample_rate_idx)),
                                              "audio", "AAC-hbr",
                                              STR(sprintf_("%02X%02X", asc[0], asc[1])),
                                              channel);
      m_audio->rtcp_socket = new RtpInterface(scheduler);
      m_audio->rtcp = new Rtcp(scheduler, m_audio->rtcp_socket, NULL, NULL);
      add_stream(m_audio->sink, m_audio->rtcp);
    }
  }

  return 0;
}

void RtspSink::add_stream(MultiFramedRTPSink *rtp_sink, Rtcp *rtcp)
{
  if (!rtp_sink) return;

  SubstreamDescriptor *new_descriptor =
    new SubstreamDescriptor(rtp_sink, rtcp, ++m_last_track_id);
  m_substream_descriptors.push_back(new_descriptor);
  m_substream_sdp_sizes += strlen(new_descriptor->sdp_lines());
}

int RtspSink::set_destination_and_play()
{
  if (!m_video->sink || !m_audio->sink)
    return 0;

  std::auto_ptr<xuri::Uri> uri_parser(new xuri::Uri);
  uri_parser->parse(STR(m_liveurl));

  unsigned const sdp_session_id = random32();
  unsigned const sdp_version = sdp_session_id;
  std::string sdp = sprintf_("v=0"CRLF
                             "o=- %u %u IN IP4 %s"CRLF
                             "s=flvpusher"CRLF
                             "i=flvpusher"CRLF
                             "c=IN IP4 %s"CRLF
                             "t=0 0"CRLF
                             "a=x-qt-text-nam:"CRLF
                             "a=x-qt-text-inf:"CRLF
                             "a=x-qt-text-cmt:source application:flvpusher"CRLF
                             "a=x-qt-text-aut:"CRLF
                             "a=x-qt-text-cpy:"CRLF,
                             sdp_session_id, sdp_version, m_our_ap.get_address(),
                             uri_parser->host);
  FOR_VECTOR_ITERATOR(SubstreamDescriptor *, m_substream_descriptors, it) {
    sdp += (*it)->sdp_lines();
  }

  if (m_client->request_announce(sdp) < 0) {
    LOGE("Failed to send ANNOUNCE command");
    return -1;
  }

  if (m_client->request_setup(sdp, true, true) < 0) {
    LOGE("Failed to send ANNOUNCE command");
    return -1;
  }

  unsigned stream_channel_id = 0;
  FOR_VECTOR_ITERATOR(SubstreamDescriptor *, m_substream_descriptors, it) {
    (*it)->rtp_sink()->set_stream_socket(m_client->get_sockfd(), stream_channel_id++);
    (*it)->rtcp()->set_stream_socket(m_client->get_sockfd(), stream_channel_id++);
  }

  if (m_client->request_play() < 0) {
    LOGE("Failed to PLAY session");
    return -1;
  }

  m_client->increate_send_buffer_to(100*1024);

  m_video->sink->set_on_send_error_func(on_send_error, this);
  m_video->sink->start_playing(m_video->queue, after_playing, m_video->sink);

  m_audio->sink->set_on_send_error_func(on_send_error, this);
  m_audio->sink->start_playing(m_audio->queue, after_playing, m_audio->sink);

  RtpInterface::set_server_request_alternative_byte_handler(
      m_client->get_sockfd(),
      RtspClient::handle_alternative_request_byte, m_client);

  return 0;
}

void RtspSink::after_playing(void *client_data)
{
  MultiFramedRTPSink *rtp_sink = (MultiFramedRTPSink *) client_data;
  rtp_sink->stop_playing();
}

void RtspSink::on_send_error(void *on_send_error_data)
{
  RtspSink *rtsp_sink = (RtspSink *) on_send_error_data;
  if (!rtsp_sink->m_send_error) {
    rtsp_sink->disconnect();
    rtsp_sink->m_send_error = true;
  }
}

/////////////////////////////////////////////////////////////

RtspSink::MediaAggregation::MediaAggregation() :
  sink(NULL), rtcp(NULL), rtp_socket(NULL), rtcp_socket(NULL)
{
}

RtspSink::MediaAggregation::~MediaAggregation()
{
  if (sink)
    sink->stop_playing();

  Frame *f;
  queue.cancel_wait();
  while (!queue.pop(f)) { SAFE_DELETE(f); }

  SAFE_DELETE(sink);
  SAFE_DELETE(rtcp);
  SAFE_DELETE(rtp_socket);
  SAFE_DELETE(rtcp_socket);
}

}
