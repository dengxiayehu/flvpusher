#include "mpeg4_generic_rtp_sink.h"
#include "rtsp_common.h"
#include "rtp_interface.h"

using namespace xutil;

namespace flvpusher {

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
