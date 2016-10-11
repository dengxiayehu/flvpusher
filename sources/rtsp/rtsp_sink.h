#ifndef _RTSP_SINK_H_
#define _RTSP_SINK_H_

#include <xmedia.h>
#include <xqueue.h>
#include <xnet.h>

#include "common/media_sink.h"

namespace flvpusher {

class MultiFramedRTPSink;
class Rtcp;
class RtpInterface;
class RtspClient;
class SubstreamDescriptor;

class RtspSink : public MediaSink {
public:
  RtspSink(const std::string &flvpath);
  virtual ~RtspSink();

  virtual Type type() const;
  virtual std::string type_str() const;

  virtual int connect(const std::string &liveurl);
  virtual int disconnect();

  virtual int send_video(int32_t timestamp, byte *dat, uint32_t length,
                         uint32_t composition_time);
  virtual int send_audio(int32_t timestamp, byte *dat, uint32_t length);

private:
  void add_stream(MultiFramedRTPSink *rtp_sink, Rtcp *rtcp);
  int set_destination_and_play();

  static void after_playing(void *client_data);
  static void on_send_error(void *on_send_error_data);

  struct MediaAggregation {
    xutil::Queue<xmedia::Frame *> queue;
    MultiFramedRTPSink *sink;
    Rtcp *rtcp;
    RtpInterface *rtp_socket;
    RtpInterface *rtcp_socket;

    MediaAggregation();
    ~MediaAggregation();
  };

private:
  xnet::AddressPort m_our_ap;
  DECL_THREAD_ROUTINE(RtspSink, proc_routine);
  xutil::Thread *m_proc_thrd;
  xutil::RecursiveMutex m_mutex;
  std::string m_liveurl;
  RtspClient *m_client;
  unsigned m_substream_sdp_sizes;
  std::vector<SubstreamDescriptor *> m_substream_descriptors;
  unsigned m_last_track_id;
  MediaAggregation *m_video, *m_audio;
  bool m_send_error;
  bool m_start_sink;
  int32_t m_first_key_frame_timestamp;
};

}

#endif /* end of _RTSP_SINK_H_ */
