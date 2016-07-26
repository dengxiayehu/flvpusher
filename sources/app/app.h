#ifndef _APP_H_
#define _APP_H_

#include <xutil.h>
#include <xconfig.h>

#include "common/config.h"

using xutil::status_t;

namespace flvpusher {

class MediaSink;
class MediaPusher;
class HLSSegmenter;

class App {
public:
    ~App();

    int main(int argc, char *argv[]);

    void ask2quit();

    static App *get_instance() {
        if (!app) {
            xutil::AutoLock l(mutex);

            if (!app) {
                app = new App;
            }
        }
        return app;
    }

private:
    DISALLOW_COPY_AND_ASSIGN(App);

    App();

    int init();
    void cleanup();

    int load_cfg(std::string cfg_file = DEFAULT_CFG_FILE);
    int parse_arg(int argc, char *argv[]);
    int check_arg() const;
    void usage() const;

    int prepare();

private:
    static App *app;
    static xutil::RecursiveMutex mutex;

    xutil::Signaler *m_sig_hdl;

    std::string m_input_str;
    std::string m_liveurl;
    bool m_webserver;
    std::string m_dvfile;
    std::string m_dafile;
    std::string m_hls_playlist;
    int m_hls_time;
    int m_hls_list_size;
    bool m_loop;
    std::string m_req_m3u8;
    std::string m_req_segment;
    std::string m_tspath;
    std::string m_flvpath;

    MediaSink *m_sink;
    MediaPusher *m_pusher;
    HLSSegmenter*m_hls;

    volatile bool m_quit;

    xconfig::Config *m_conf;
};

}

#endif /* end of _APP_H_ */
