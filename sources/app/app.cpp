#include <libgen.h>
#include <memory>
#include <vector>
#include <cstdlib>
#include <getopt.h>
#include <xlog.h>
#include <xuri.h>

#include "app.h"
#include "common/config.h"
#include "flv/flv_pusher.h"
#if defined (VERSION) && (VERSION > 1)
# include "mp4/mp4_pusher1.h"
#else
# include "mp4/mp4_pusher.h"
#endif
#include "ts/ts_pusher.h"
#include "hls/hls_pusher.h"
#include "rtmp/rtmp_source.h"
#include "rtsp/rtsp_source.h"
#include "server/web_server.h"
#include "hls/hls_segmenter.h"
#include "rtsp/rtsp_sink.h"
#include "rtmp/rtmp_sink.h"

using namespace xutil;
using namespace xconfig;
using namespace xuri;

namespace flvpusher {

App *App::app = NULL;
RecursiveMutex App::mutex;

static void sighandler(int signo);
static int on_config_change(const char *conf_name, const char *value, void *user);

App::App() :
    m_sig_hdl(Signaler::get_instance()),
    m_webserver(false),
    m_hls_time(5),
    m_loop(false),
    m_sink(NULL),
    m_pusher(NULL),
    m_hls(NULL),
    m_quit(false),
    m_conf(NULL)
{
    if (init() < 0) {
        LOGE("App::init() failed, quit program");

        cleanup();
        exit(EXIT_FAILURE);
    }
}

App::~App()
{
    cleanup();
}

int App::init()
{
    if (m_sig_hdl->install(sighandler,
                           SIGINT, SIGALRM, Signaler::SIGLIST_END) != SUCCESS) {
        LOGE("Install SIGINT's handler failed");
        return -1;
    }
    if (m_sig_hdl->install(SIG_IGN,
                           SIGPIPE, Signaler::SIGLIST_END) != SUCCESS) {
        LOGE("Install SIGPIPE's handler failed");
        return -1;
    }

    return 0;
}

void App::cleanup()
{
    SAFE_DELETE(m_pusher);
    SAFE_DELETE(m_hls);
    SAFE_DELETE(m_sink);
    SAFE_DELETE(m_sig_hdl);

    if (m_conf) {
        destroy_config(&m_conf);
    }

    xlog::log_close();
}

void App::ask2quit()
{
    m_quit = true;

    if (m_pusher) m_pusher->ask2quit();
    if (m_sink) m_sink->ask2quit();
    if (m_hls) m_hls->ask2quit();
}

int App::load_cfg(std::string cfg_file)
{
    if (!is_path_absolute(STR(cfg_file))) {
        cfg_file = sprintf_("%s%c%s",
                            STR(dirname_(abs_program)), DIRSEP, STR(cfg_file));
    }
    if (!is_file(cfg_file)) {
        // It's ok if config file is missing
        return 0;
    }

    m_conf = create_config(STR(cfg_file));
    if (!m_conf) {
        LOGE("create config failed");
        return -1;
    }
    m_conf->register_config_update_cb(on_config_change, this);
    m_conf->register_config("debug_level");
    return 0;
}

int App::parse_arg(int argc, char *argv[])
{
    struct option longopts[] = {
        {"input",           required_argument, NULL, 'i'},
        {"live",            required_argument, NULL, 'L'},
        {"help",            required_argument, NULL, 'h'},
        {"dvfile",          required_argument, NULL, 'v'},
        {"dafile",          required_argument, NULL, 'a'},
        {"hls_playlist",    required_argument, NULL, 'p'},
        {"hls_time",        required_argument, NULL, 't'},
        {"hls_segment",     required_argument, NULL, 'S'},
        {"loop",            no_argument,       NULL, 'T'},
        {"tspath",          required_argument, NULL, 's'},
        {"flvpath",         required_argument, NULL, 'f'},
        {"no_logfile",      no_argument,       NULL, 'N'},
        {"webserver",       no_argument,       NULL, 'w'},
        {0, 0, 0, 0}
    };
    int ch;
    bool no_logfile = false;

    while ((ch = getopt_long(argc, argv, ":i:L:hv:a:tp:s:S:Tt:Nf:wW;", longopts, NULL)) != -1) {
        switch (ch) {
        case 'i':
            m_input_str = optarg;
            break;

        case 'L':
            m_liveurl = optarg;
            break;

        case 'v':
            if (is_file(optarg)) rm_(optarg);
            m_dvfile = optarg;
            break;

        case 'a':
            if (is_file(optarg)) rm_(optarg);
            m_dafile = optarg;
            break;

        case 'p':
            m_hls_playlist = optarg;
            break;

        case 't':
            m_hls_time = atoi(optarg);
            break;

        case 'S':
            m_req_segment = optarg;
            break;

        case 'T':
            m_loop = true;
            break;

        case 's':
            if (is_file(optarg))
                rm_(optarg);
            m_tspath = optarg;
            break;

        case 'f':
            m_flvpath = optarg;
            break;

        case 'N':
            no_logfile = true;
            break;

        case 'w':
            m_webserver = true;
            break;

        case 'h':
            usage();
            cleanup();
            exit(EXIT_SUCCESS);
            break;

        case 0:
            break;

        case '?':
        default:
            LOGE("Unknown option: %c", optopt);
            return -1;
        }
    }

    if (!no_logfile) {
        if (xlog::log_add_dst(STR(sprintf_("%s/flvpusher_log_%d.txt",
                                           LOG_DIR, getpid()))) != SUCCESS) {
            fprintf(stderr, "Init xlog system failed\n");
            return -1;
        }

        if (m_conf) {
            DECL_GET_CONFIG_STRING(m_conf, debug_level);
            xlog::set_log_level(STR(debug_level));
        }
    }

    return 0;
}

int App::check_arg() const
{
    if (!m_req_segment.empty()) {
        return 0;
    }

    if (m_webserver) {
        return 0;
    }

    if (m_input_str.empty()) {
        LOGE("No input url specified");
        return -1;
    }

    if ((m_liveurl.empty() && m_hls_playlist.empty()) ||
        (!m_liveurl.empty() && !m_hls_playlist.empty())) {
        LOGE("'--hls_playlist' and '-L' can't be both set or empty");
        return -1;
    }

    if (!m_hls_playlist.empty()) {
        if (m_hls_time < 0) {
            LOGE("Invalid value of hls_time(%d)", m_hls_time);
            return -1;
        }
    }
    return 0;
}

void App::usage() const
{
    fprintf(stderr, "flvpusher (V: %d)\n\n"
                    "Usage: flvpusher <-i source|-w> <-L liveurl [--loop] [-a dump_audio] [-v dump_video] [-s tspath] [-f flvpath]|--hls_playlist filename [--hls_time time]> [-h] [--no_logfile]\n"
                    "Description: \n"
                    "-i, --input\n"
                    "       input source, file category: *.flv, *.mp4, *.3gp *.3gpp, *.ts\n"
                    "                     protocol category: rtmp://*, rtsp://*, http://*.m3u8\n"
                    "-L, --live\n"
                    "       liveurl, inject audio&video to rtmp-server or rtsp-server,\n"
                    "       format: rtmp://<ip>[:port]/live/<rtmp-stream-name>\n"
                    "               rtsp://<ip>[:port]/<rtsp-sdp-name>.sdp\n"
                    "       note: this option is exclusive with -p and -w\n"
                    "-p, --hls_playlist\n"
                    "       pre-process flv or mp4 file to generate *.m3u8, *.m3u8.seek and hls_info.txt for dynamic hls vod\n"
                    "       note: this option is exclusive with -L and -w\n"
                    "-t, --hls_time\n"
                    "       specify the ts-segment's duration in hls vod\n"
                    "-w, --webserver\n"
                    "       start webserver\n"
                    "       note: this option is exclusive with -L and -p\n"
                    "-T, --loop\n"
                    "       if input source is done, start it over again\n"
                    "-N, --no_logfile\n"
                    "       do NOT generate log file, run this program in slience\n"
                    "-v, --dvfile\n"
                    "       dump raw video into file (format: H.264)\n"
                    "-a, --dafile\n"
                    "       dump raw audio into file (format: AAC)\n"
                    "-f, --flvpath\n"
                    "       dump video&audio into flv\n"
                    "-s, --tspath\n"
                    "       dump video&audio into ts\n"
                    "-h, --help\n"
                    "       show this help message and quit\n\n\n"
                    "Sample:\n"
                    "1. stream mp4 to rtmpserver (other input sources are the same)\n"
                    "$ flvpusher -i ~/Video/omn.mp4 -L rtmp://127.0.0.1:1935/live/va\n\n"
                    "2. stream mp4 to rtspserver (ditto)\n"
                    "$ flvpusher -i ~/Video/omn.mp4 -L rtsp://192.168.119.1/va.sdp\n\n"
                    "3. pre-process mp4 to prepare for hls dynamic vod\n"
                    "$ flvpusher -i ~/Video/omn.mp4 --hls_playlist html/omn/omn.m3u8 --hls_time 5\n\n"
                    "4. start webserver for hls vod\n"
                    "$ flvpusher -w\n"
                    "note: a. webserver server's root directory is default to ./html\n"
                    "      b. webserver server's port is default to 9877\n"
                    "      c. use player(e.g. vlc) to play this hls vod: http://<this-server-ip:9877>/omn/omn.m3u8\n"
                    "      d. you can modify root directory and listen port in flvpusher_cfg.txt, and put it in the same\n"
                    "         directory with this tool\n"
                    , VERSION);
}

int App::prepare()
{
    if (!m_liveurl.empty()) {
        if (start_with(m_liveurl, "rtmp://")) {
            m_sink = new RtmpSink(m_flvpath);
        } else if (start_with(m_liveurl, "rtsp://")) {
            if (!end_with(m_liveurl, ".sdp")) {
                LOGE("Invalid rtsp live url: \"%s\"", STR(m_liveurl));
                return -1;
            }
            m_sink = new RtspSink(m_flvpath);
        }
        if (m_sink->connect(m_liveurl) < 0)
            return -1;
    }
    return 0;
}

int App::main(int argc, char *argv[])
{
    if (load_cfg() < 0) {
        return -1;
    }

    if (parse_arg(argc, argv) < 0 ||
        check_arg() < 0) {
        usage();
        return 1;
    }

    if (!m_req_segment.empty()) {
        return HLSSegmenter::create_segment(m_req_segment);
    }

    int ret = 0;

    if (m_webserver) {
        std::auto_ptr<WebServer> webserver(new WebServer(m_conf));

        int listen_port = DEFAULT_LISTEN_PORT,
            server_threads = DEFAULT_SERVER_THREADS;
        if (m_conf) {
            GET_CONFIG_INT(m_conf, listen_port);
            GET_CONFIG_INT(m_conf, server_threads);
        }

        if (webserver->start(listen_port, server_threads) < 0) {
            LOGE("Start webserver failed");
            return -1;
        }

        while (!m_quit) {
            if (webserver->pulse() < 0) {
                ret = -1;
                break;
            }
            short_snap(1000, &m_quit);
        }

        webserver->stop();
        return ret;
    }

    if (prepare() < 0) {
       return -1;
    }

    std::vector<std::string> input(
            xutil::split(m_input_str, INPUT_SEPARATOR));

    if (!m_hls_playlist.empty()) {
        if (!end_with(m_hls_playlist, ".m3u8")) {
            LOGE("Not a valid m3u8 file \"%s\"", STR(m_hls_playlist));
            return -1;
        }

        m_hls = new HLSSegmenter(
                m_hls_playlist, // Path of *.m3u8
                m_hls_time      // Desired ts-segment's duration
                );
        ret = m_hls->set_file(input[0], m_loop);
        if (ret < 0)
            return ret;
        return m_loop ? m_hls->loop() : 0;
    }

    while (!m_quit) {
        foreach(input, it) {
            if (m_quit) break;

            if (start_with(*it, "rtmp://")) {
                m_pusher = new RtmpSource(*it, m_sink);
            } else if (start_with(*it, "rtsp://")) {
                m_pusher = new RtspSource(*it, m_sink);
            } else if (end_with(*it, ".flv")) {
                m_pusher = new FLVPusher(*it, m_sink);
            } else if (end_with(*it, ".mp4") ||
                       end_with(*it, ".3gp") || end_with(*it, ".3gpp")) {
#if defined (VERSION) && (VERSION > 1)
                m_pusher = new MP4Pusher1(*it, m_sink);
#else
                m_pusher = new MP4Pusher(*it, m_sink);
#endif
            } else if (end_with(*it, ".ts")) {
                m_pusher = new TSPusher(*it, m_sink);
            } else if (start_with(*it, "http://")) {
                std::auto_ptr<Uri> uri_parser(new Uri);
                uri_parser->parse(STR(*it));
                if (end_with(uri_parser->path, ".m3u8")) {
                    m_pusher = new HLSPusher(*it, m_sink, m_conf);
                }
            }

            if (!m_pusher) {
                LOGE("Media file \"%s\" not supported (ignored)",
                     STR(*it));
                continue;
            }

            m_pusher->dump_video(m_dvfile);
            m_pusher->dump_audio(m_dafile);
            m_pusher->mux2ts(m_tspath);
            if (m_pusher->loop() < 0) {
                SAFE_DELETE(m_pusher);
                break;
            }

            SAFE_DELETE(m_pusher);
        }

        if (!m_loop) {
            // No need to loop push, quit
            ask2quit();
            break;
        }
    }

    return 0;
}

static void sighandler(int signo)
{
    if (signo == SIGINT) {
        App::get_instance()->ask2quit();
    }
}

static int on_config_change(const char *conf_name, const char *value, void *user)
{
    if (conf_name && value && !strncmp(conf_name, "debug_level", 11))
        xlog::set_log_level(value);
    return 0;
}

}
