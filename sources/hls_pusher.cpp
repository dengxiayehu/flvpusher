#include <memory>
#include <xlog.h>
#include <xcurl.h>

#include "hls_pusher.h"
#include "hls_common.h"

using namespace xconfig;
using namespace xcurl;
using namespace xutil;
using namespace std;

namespace flvpusher {

HLSPusher::HLSPusher(const string &input, RtmpHandler *&rtmp_hdl, Config *conf) :
    MediaPusher(input, rtmp_hdl),
    m_conf(conf), m_sys(NULL), m_tempdir(strdup_("flvpusher-XXXXXX"))
{
}

HLSPusher::~HLSPusher()
{
    system_("rm -rf %s", m_tempdir);
    SAFE_FREE(m_tempdir);
    SAFE_DELETE(m_sys);
}

HLSPusher::StreamSys::StreamSys(Config *c, string uri) :
    conf(c), m3u8(uri), bandwithd(0), cache(false), meta(false), live(true)
{
}

HLSPusher::StreamSys::~StreamSys()
{
}

int HLSPusher::prepare()
{
    if (!mkdtemp(m_tempdir)) {
        LOGE("mkdtemp failed: %s", ERRNOMSG);
        return -1;
    }

    m_sys = new StreamSys(m_conf, m_input);

    auto_ptr<IOBuffer> iobuf(new IOBuffer);
    if (read_M3U8_from_uri(m_sys, STR(m_input), iobuf.get()) < 0) {
        LOGE("read_M3U8_from_uri(%s) failed", STR(m_input));
        return -1;
    }

    if (!is_valid_m3u8(GETIBPOINTER(*iobuf), GETAVAILABLEBYTESCOUNT(*iobuf))) {
        LOGE("Validate uri \"%s\"'s content failed", STR(m_input));
        return -1;
    }
    return 0;
}

int HLSPusher::loop()
{
    if (prepare() < 0) {
        LOGE("HLSPusher's prepare() failed");
        return -1;
    }
    
    LOGI("Pushing hls \"%s\" ..", STR(m_input));
    return 0;
}

int HLSPusher::read_content_from_uri(int timeout, bool verbose, bool trace_ascii,
                                     const char *uri, IOBuffer *iobuf)
{
    auto_ptr<Curl> curl(new Curl);
    Curl::request *req =
        Curl::request::build(Curl::GET, uri, Curl::write_cb, iobuf, timeout, NULL,
                             verbose, trace_ascii, true, true);
    if (!req) {
        LOGE("Build GET for uri \"%s\" failed", uri);
        return -1;
    }
    if (curl->perform(req, NULL) < 0 ||
        req->response_code != 200) {
        LOGE("read_content_from_url(%s) failed (response_code=%d)",
             uri, req->response_code);
        Curl::request::recycle(&req);
        return -1;
    }
    Curl::request::recycle(&req);
    return 0;
}

int HLSPusher::read_M3U8_from_uri(StreamSys *sys, const char *uri, IOBuffer *iobuf)
{
    DECL_GET_CONFIG_INT(sys->conf, curl_hls_timeout);
    DECL_GET_CONFIG_BOOL(sys->conf, curl_verbose);
    DECL_GET_CONFIG_BOOL(sys->conf, curl_trace_ascii);
    return read_content_from_uri(curl_hls_timeout, curl_verbose, curl_trace_ascii,
                                 uri, iobuf);;
}

}
