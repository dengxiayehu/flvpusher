#include <xlog.h>

#include "rtsp_sink.h"
#include "rtsp_common.h"

namespace flvpusher {

class SubstreamDescriptor {
};

/////////////////////////////////////////////////////////////

RtspSink::RtspSink(const std::string &flvpath) :
    MediaSink(flvpath), m_last_track_id(0)
{
    m_client = new RtspClient(NULL);
}

RtspSink::~RtspSink()
{
    SAFE_DELETE(m_client);
}

MediaSink::Type RtspSink::type() const
{
    return RTSP_SINK;
}

int RtspSink::connect(const std::string &liveurl)
{
    AddressPort ap(our_ip(), 0);
    if (m_client->open(liveurl, ap) < 0)
        return -1;

    if (m_client->request_options(
                (TaskFunc *) RtspClient::continue_after_option) < 0) {
        LOGE("Failed to send OPTION command");
        return -1;
    }

    return 0;
}

int RtspSink::disconnect()
{
    return 0;
}

int RtspSink::send_video(int32_t timestamp, byte *dat, uint32_t length)
{
    return 0;
}

int RtspSink::send_audio(int32_t timestamp, byte *dat, uint32_t length)
{
    return 0;
}

}
