#include <xlog.h>

#include "rtsp_source.h"
#include "rtsp_client.h"
#include "common/media_sink.h"

using namespace std;

namespace flvpusher {

RtspSource::RtspSource(const std::string &input, MediaSink *&sink) :
  MediaPusher(input, sink)
{
  m_client = new RtspClient(this);
}

RtspSource::~RtspSource()
{
  RtspClient::shutdown_stream(m_client);
  SAFE_DELETE(m_client);
}

int RtspSource::loop()
{
  if (prepare() < 0) {
    LOGE("RtspSource's prepare() failed");
    return -1;
  }

  return m_client->loop(interrupt_variable());
}

int RtspSource::prepare()
{
  AddressPort ap(our_ip(), 0);
  if (m_client->open(m_input, ap) < 0)
    return -1;

  if (m_client->request_options(
        (TaskFunc *) RtspClient::continue_after_options) < 0) {
    LOGE("Failed to send OPTIONS command");
    return -1;
  }

  string sdp;
  if (m_client->request_describe(sdp,
                                 (TaskFunc *) RtspClient::continue_after_describe) < 0) {
    LOGE("Failed to send DESCRIBE command");
    return -1;
  }

  if (m_client->request_setup(sdp) < 0) {
    LOGE("Failed to SETUP the subsessions");
    return -1;
  }

  if (m_client->request_play() < 0) {
    LOGE("Failed to PLAY session");
    return -1;
  }

  return 0;
}

int RtspSource::on_frame(const int32_t ts,
                         const byte *dat, const uint32_t dat_len, int is_video)
{
  MediaPusher::on_frame(ts, dat, dat_len, is_video);

  if (is_video)
    return m_sink->send_video(ts, (byte *) dat, dat_len);
  else
    return m_sink->send_audio(ts, (byte *) dat, dat_len);
}

}
