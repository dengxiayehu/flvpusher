#include "media_pusher.h"
#include "rtmp_handler.h"

using namespace xmedia;

namespace flvpusher {

MediaPusher::MediaPusher(const std::string &input,
    RtmpHandler *&rtmp_hdl) :
    m_input(input),
    m_rtmp_hdl(rtmp_hdl),
    m_quit(false),
    m_itime_base((AVRational) {1001, 24000})
{
}

MediaPusher::~MediaPusher()
{
    m_dvf.close();
    m_daf.close();
}

int MediaPusher::dump_video(const std::string &path)
{
    if (path.empty()) return 0;

    if (m_dvf.is_opened())
        m_dvf.close();

    return m_dvf.open(STR(path), "wb+") ? 0 : -1;
}

int MediaPusher::dump_audio(const std::string &path)
{
    if (path.empty()) return 0;

    if (m_daf.is_opened())
        m_daf.close();

    return m_daf.open(STR(path), "wb+") ? 0 : -1;
}

int MediaPusher::mux2ts(const std::string &tspath)
{
    m_tspath = tspath;
    return 0;
}

int MediaPusher::on_frame(const int32_t ts,
        const byte *dat, const uint32_t dat_len, int is_video)
{
    if (is_video && m_dvf.is_opened()) {
        if (!m_dvf.write_buffer(dat, dat_len))
            return -1;
    }
    
    if (!is_video && m_daf.is_opened()) {
        if (!m_daf.write_buffer(dat, dat_len))
            return -1;
    }

    if (!m_tspath.empty()) {
        if (!m_tsmuxer.is_opened()) {
            AutoLock _l(m_mutex);
            if (!m_tsmuxer.is_opened()) {
                // itime_base for pcr generation
                if (m_tsmuxer.set_file(m_tspath, m_itime_base) < 0)
                    return -1;
            }
        }

        if (m_tsmuxer.write_frame(ts, dat, dat_len, is_video) < 0)
            return -1;
    }

    return 0;
}

}
