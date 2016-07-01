#include <xlog.h>

#include "rtsp_sink.h"
#include "rtsp_common.h"

namespace flvpusher {

RtspSink::RtspSink(const std::string &flvpath) :
    MediaSink(flvpath)
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
