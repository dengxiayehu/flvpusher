#ifndef _MPEG4_GENERIC_RTP_SINK_H_
#define _MPEG4_GENERIC_RTP_SINK_H_

#include "multi_framed_rtp_sink.h"

namespace flvpusher {

class TaskScheduler;
class RtpInterface;

class MPEG4GenericRTPSink : public MultiFramedRTPSink {
public:
    MPEG4GenericRTPSink(TaskScheduler *scheduler, RtpInterface *interface, unsigned char rtp_payload_format,
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

#endif /* end of _MPEG4_GENERIC_RTP_SINK_H_ */
