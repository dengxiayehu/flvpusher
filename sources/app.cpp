#include "app.h"

#include <libgen.h>
#include <memory>
#include <vector>

#include <xlog.h>

#include <cstdlib>
#include <getopt.h>

#include "config.h"

#include "flv_pusher.h"
#if defined (VERSION) && (VERSION > 1)
# include "mp4_pusher1.h"
#else
# include "mp4_pusher.h"
#endif
#include "ts_pusher.h"
#include "rtmp_source.h"
#include "rtsp_source.h"
#include "hls_segmenter.h"
#include "rtmp_handler.h"
#include "config.h"

using namespace xutil;

namespace flvpusher {

App *App::app = NULL;
RecursiveMutex App::mutex;

static void sighandler(int signo);

App::App() :
    m_sig_hdl(Signaler::get_instance()),
    m_hls_time(5), m_hls_list_size(INT32_MAX),
    m_loop(false),
    m_rtmp_hdl(NULL),
    m_pusher(NULL),
    m_hls(NULL),
    m_quit(false)
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
                SIGINT, Signaler::SIGLIST_END) != SUCCESS) {
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
    SAFE_DELETE(m_rtmp_hdl);
    SAFE_DELETE(m_hls);
    SAFE_DELETE(m_sig_hdl);

    xlog::log_close();
}

void App::ask2quit()
{
    m_quit = true;

    if (m_pusher)
        m_pusher->ask2quit();
    if (m_hls)
        m_hls->ask2quit();
}

int App::load_cfg(const char *cfg_file)
{
    /* NOTE: config file's format:
     * RTMPSRV_IP=127.0.0.1
     * RTMPSRV_PORT=1935 */

    FILE *fp = fopen(cfg_file, "r");
    if (!fp) return -1; // It's ok if cfg file not exists

    LOGI("Loading cfg file \"%s\" ..", cfg_file);

    std::string ip;
    uint16_t port = 1935;

    char buf[MaxLine];
    while (fgets(buf, sizeof(buf), fp)) {
        // Ignore buf starts with '#'
        if ('#' == buf[0]) continue;

        // Remove trailing '\n' if exists
        int len = strlen(buf);
        if (buf[len - 1] == '\n')
            buf[len - 1] = '\0';

        std::vector<std::string> vpart(split(buf, "="));
        if (vpart[0] == "RTMPSRV_IP")
            ip = vpart[1];
        else if (vpart[0] == "RTMPSRV_PORT")
            port = atoi(STR(vpart[1]));
    }

    // To see whether error occurred
    if (ferror(fp)) {
        LOGE("Parse cfg file \"%s\" failed: %s (cont)",
                cfg_file, ERRNOMSG);
    }

    // Make liveurl
    m_liveurl = sprintf_("rtmp://%s:%u/live/va%d",
            STR(ip), port, getpid());

    fclose(fp);
    return 0;
}

int App::parse_arg(int argc, char *argv[])
{
    struct option longopts[] = {
        {"input",           required_argument, NULL, 'i'},
        {"live",            required_argument, NULL, 'L'},
        {"log-level",       required_argument, NULL, 'l'},
        {"help",            required_argument, NULL, 'h'},
        {"dvfile",          required_argument, NULL, 'v'},
        {"dafile",          required_argument, NULL, 'a'},
        {"hls_playlist",    required_argument, NULL, 'S'},
        {"hls_time",        required_argument, NULL, 't'},
        {"hls_list_size",   required_argument, NULL, 'z'},
        {"hls_client",      required_argument, NULL, 'c'},
        {"loop",            no_argument,       NULL, 'T'},
        {"tspath",          required_argument, NULL, 's'},
        {"flvpath",         required_argument, NULL, 'f'},
        {"no_logfile",      no_argument,       NULL, 'N'},
        {0, 0, 0, 0}
    };
    int ch;
    bool no_logfile = false;

    while ((ch = getopt_long(argc, argv, ":i:L:l:hv:a:tS:s:Tt:z:c:Nf:W;", longopts, NULL)) != -1) {
        switch (ch) {
        case 'i':
            m_input_str = optarg;
            break;

        case 'L':
            m_liveurl = optarg;
            break;

        case 'l': {
            xlog::log_level loglvl = xlog::DEBUG;
            if      (!strcasecmp(optarg, "DEBUG"))  loglvl = xlog::DEBUG;
            else if (!strcasecmp(optarg, "INFO"))   loglvl = xlog::INFO;
            else if (!strcasecmp(optarg, "WARN"))   loglvl = xlog::WARN;
            else if (!strcasecmp(optarg, "ERROR"))  loglvl = xlog::ERROR;
            else {
                LOGE("Invalid log level \"%s\"", optarg);
                return -1;
            }
            xlog::set_log_level(loglvl);
            } break;

        case 'v':
            m_dvfile = optarg;
            break;

        case 'a':
            m_dafile = optarg;
            break;

        case 'S':
            m_hls_playlist = optarg;
            break;

        case 't':
            m_hls_time = atoi(optarg);
            break;

        case 'z':
            m_hls_list_size = atoi(optarg);
            break;

        case 'T':
            m_loop = true;
            break;

        case 's':
            m_tspath = optarg;
            break;

        case 'f':
            m_flvpath = optarg;
            break;

        case 'c':
            m_req_tspath = optarg;
            break;

        case 'N':
            no_logfile = true;
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
        if (xlog::log_add_dst(STR(sprintf_("%s/flvpusher_log_%d.txt", LOG_DIR, getpid()))) != SUCCESS) {
            fprintf(stderr, "Init xlog system failed\n");
            return -1;
        }
    }
    return 0;
}

int App::check_arg() const
{
    if (m_req_tspath.empty()) {
        if (m_input_str.empty()) {
            LOGE("No input file specified");
            return -1;
        }

        if ((m_liveurl.empty() && m_hls_playlist.empty()) ||
            (!m_liveurl.empty() && !m_hls_playlist.empty())) {
            LOGE("'--hls_playlist' and '-L' can't be both set or empty");
            return -1;
        }
    }

    if (!m_hls_playlist.empty()) {
        if (m_hls_time < 0 || m_hls_list_size < 0) {
            LOGE("Invalid value of hls_time(%d) or hls_list_size(%d)",
                    m_hls_time, m_hls_list_size);
            return -1;
        }
    }

    return 0;
}

void App::usage() const
{
    fprintf(stderr, "Usage: flvpusher <-i media_file> <-L liveurl [--loop] [-a dump_audio] [-v dump_video] [-s tspath] [-f flvpath]|--hls_playlist filename [--hls_time time] [--hls_list_size size]|[-c request-tspath]> [-h] [-l log_level|--no_logfile]\n");
    fprintf(stderr, "Version: %d\n", VERSION);
}

int App::prepare()
{
    if (!m_liveurl.empty()) {
        m_rtmp_hdl = new RtmpHandler(m_flvpath);
        if (m_rtmp_hdl->connect(m_liveurl) < 0)
            return -1;
    }
    return 0;
}

int App::main(int argc, char *argv[])
{
    // Load config file from exe's dir
    if (load_cfg(STR(sprintf_("%s/%s",
                              STR(dirname_(argv[0])), CFG_FILE))) < 0) {
        // Fall through
    }

    if (parse_arg(argc, argv) < 0 ||
        check_arg() < 0) {
        usage();
        return 1;
    }

    if (prepare() < 0)
       return -1;

    std::vector<std::string> input(
            xutil::split(m_input_str, INPUT_SEPARATOR));

    if (!m_hls_playlist.empty()) {
        if (!end_with(m_hls_playlist, ".m3u8")) {
            LOGE("Not a valid m3u8 file \"%s\"",
                    STR(m_hls_playlist));
            return -1;
        }

        m_hls = new HLSSegmenter(
                m_hls_playlist, // Path of *.m3u8
                m_hls_time,     // Desired ts-segment's duration
                m_hls_list_size // Max# of ts-segments
                );
        int ret = m_hls->set_file(input[0], m_loop);
        if (ret < 0)
            return -1;
        else if (ret > 0)
            return 0;
        return m_loop ? m_hls->loop() : 0;
    }

    while (!m_quit) {
        foreach(input, it) {
            if (m_quit) break;

            if (start_with(*it, "rtmp://")) {
                m_pusher = new RtmpSource(*it, m_rtmp_hdl);
            } else if (start_with(*it, "rtsp://")) {
                m_pusher = new RtspSource(*it, m_rtmp_hdl);
            } else if (end_with(*it, ".flv")) {
                m_pusher = new FLVPusher(*it, m_rtmp_hdl);
            } else if (end_with(*it, ".mp4")) {
#if defined (VERSION) && (VERSION > 1)
                m_pusher = new MP4Pusher1(*it, m_rtmp_hdl);
#else
                m_pusher = new MP4Pusher(*it, m_rtmp_hdl);
#endif
            } else if (end_with(*it, ".ts")) {
                m_pusher = new TSPusher(*it, m_rtmp_hdl);
            } else {
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
    App::get_instance()->ask2quit();
}

}
