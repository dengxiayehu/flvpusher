#include <sys/stat.h>
#include <memory>
#include <mongoose.h>
#include <xlog.h>
#include <xcurl.h>

#include "web_server.h"
#include "config.h"

#define IMPL(x) ((WebServerImpl *) (x))

using namespace xutil;
using namespace xconfig;
using namespace xcurl;
using namespace std;

namespace flvpusher {

class WebServerImpl {
public:
    WebServerImpl(xconfig::Config *conf);
    virtual ~WebServerImpl();

    int start(int listen_port, int server_threads);
    int stop();

    static int send_response(struct mg_connection *conn, const char *code_desc,
                             const char *content_type = "text/plain", int content_length = 0,
                             bool close_connection = true, uint8_t *content = NULL);

private:
    enum { kMaxOptions = 100 };
    static void set_option(char **options, const char *name, const char *value);
    static char *get_option(char **options, const char *option_name);
    static int is_path_absolute(const char *path);
    static void set_absolute_path(char *options[], const char *option_name,
                                  const char *program);
    static bool verify_existence(char **options, const char *name, bool dir);
    static int ev_handler(struct mg_connection *conn, enum mg_event ev);
    struct ServeParam {
        struct mg_server *server;
        void *user;
        void *thread_id;
        uint64_t prev_poll;
    };
    static void *serve(void *param);
    static int serve_request(struct mg_connection *conn);
    static int serve_auth(struct mg_connection *conn);
    static bool is_index(const char *uri);

private:
    DISALLOW_COPY_AND_ASSIGN(WebServerImpl);
    Config *m_conf;
    RecursiveMutex m_mutex;
    vector<ServeParam *> m_serve_param;
    volatile bool m_quit;
};

WebServerImpl::WebServerImpl(Config *conf) :
    m_conf(conf), m_quit(false)
{
}

WebServerImpl::~WebServerImpl()
{
}

int WebServerImpl::start(int listen_port, int server_threads)
{
    if (listen_port < 1024 || listen_port > 65535 ||
        server_threads < 1) {
        LOGE("Invalid start param (%d,%d)", listen_port, server_threads);
        return -1;
    }

    if (!m_serve_param.empty()) {
        LOGE("WebServer already started");
        return -1;
    }

    for (int i = 0; i < server_threads; ++i) {
        ServeParam *sp = new ServeParam;
        sp->server =
            mg_create_server(this, (mg_handler_t) ev_handler);
        sp->user = this;
        sp->thread_id = NULL;
        sp->prev_poll = get_time_now();
        m_serve_param.push_back(sp);
    }

    string document_root = DEFAULT_DOCUMENT_ROOT;
    if (m_conf) {
        GET_CONFIG_STRING(m_conf, document_root);
    }
    if (!is_dir(document_root)) {
        system_("mkdir -p %s", STR(document_root));
    }

    char *options[kMaxOptions] = { NULL };
    set_option(options, "document_root", STR(document_root));
    set_option(options, "listening_port", STR(sprintf_("%d", listen_port)));

    set_absolute_path(options, "document_root", abs_program);
    set_absolute_path(options, "dav_auth_file", abs_program);
    set_absolute_path(options, "cgi_interpreter", abs_program);
    set_absolute_path(options, "access_log_file", abs_program);
    set_absolute_path(options, "global_auth_file", abs_program);
    set_absolute_path(options, "ssl_certificate", abs_program);

    verify_existence(options, "document_root", true);
    verify_existence(options, "cgi_interpreter", false);
    verify_existence(options, "ssl_certificate", false);

    for (int i = 0; options[i]; i += 2) {
        FOR_VECTOR_ITERATOR(ServeParam *, m_serve_param, it) {
            const char *msg = mg_set_option((*it)->server,
                                            options[i], options[i + 1]);
            if (msg) {
                LOGE("Server#%d Failed to set option [%s] to [%s]: %s",
                     distance(it, m_serve_param.end()),
                     options[i], options[i + 1], msg);
            }
            if (!strcmp(options[i], "listening_port"))
                break;
        }
        SAFE_FREE(options[i]);
        SAFE_FREE(options[i + 1]);
    }

    chdir(STR(document_root));

    for (int i = 1; i < server_threads; ++i) {
        mg_copy_listeners(m_serve_param[0]->server, m_serve_param[i]->server);
    }

    FOR_VECTOR_ITERATOR(ServeParam *, m_serve_param, it) {
        (*it)->thread_id = mg_start_thread(serve, *it);
        LOGD("Server#%d (thread:%p) started",
             distance(it, m_serve_param.end()), (*it)->thread_id);
    }

    return 0;
}

int WebServerImpl::stop()
{
    if (!m_quit) {
        m_quit = true;

        FOR_VECTOR_ITERATOR(ServeParam *, m_serve_param, it) {
            mg_destroy_server(&(*it)->server);
            LOGD("Server#%d (thread:%p) ended",
                 distance(it, m_serve_param.end()), (*it)->thread_id);
            SAFE_DELETE((*it));
        }
    }
    return 0;
}

void WebServerImpl::set_option(char **options, const char *name, const char *value)
{
    int i;

    for (i = 0; i < kMaxOptions - 3; i += 2) {
        if (!options[i]) {
            options[i] = strdup(name);
            options[i + 1] = strdup(value);
            options[i + 2] = NULL;;
            break;
        } else if (!strcmp(options[i], name)) {
            SAFE_FREE(options[i + 1]);
            options[i + 1] = strdup(value);
            break;
        }
    }

    if (i == kMaxOptions - 3) {
        LOGE("Too many options specified");
    }
}

char *WebServerImpl::get_option(char **options, const char *option_name)
{
    for (int i = 0; options[i]; i += 2) {
        if (!strcmp(options[i], option_name))
            return options[i + 1];
    }

    return NULL;
}

int WebServerImpl::is_path_absolute(const char *path)
{
    return path && path[0] == '/';
}

void WebServerImpl::set_absolute_path(char *options[], const char *option_name,
                                      const char *program)
{
    char path[PATH_MAX], abs[PATH_MAX], *option_value;
    const char *p;

    option_value = get_option(options, option_name);
    if (option_value && !is_path_absolute(option_value)) {
        if (!(p = strrchr(program, DIRSEP))) {
            getcwd(path, sizeof(path));
        } else {
            snprintf(path, sizeof(path), "%.*s", (int) (p - program),
                     program);
        }

        strncat(path, "/", sizeof(path) - 1);
        strncat(path, option_value, sizeof(path) - 1);

        ABS_PATH(path, abs, sizeof(abs));
        set_option(options, option_name, abs);
    }
}

bool WebServerImpl::verify_existence(char **options, const char *name, bool dir)
{
    const char *path = get_option(options, name);
    if (!((path && ((dir && is_dir(path)) || (!dir && is_file(path)))) || !path)) {
        LOGE("Invalid path for %s: [%s]. Make sure that path is either "
             "absolute, or it is relative to program",
             name, path);
        return false;
    }
    return true;
}

int WebServerImpl::ev_handler(struct mg_connection *conn, enum mg_event ev)
{
    switch (ev) {
    case MG_REQUEST: return serve_request(conn);
    case MG_AUTH: return serve_auth(conn);
    default: return MG_FALSE;
    }
}

const static char *html_index = "<html><head><title>Welcome to flvpusher!</title><style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;}</style></head><body><h1>Welcome to flvpusher!</h1><p>If you see this page, the server is successfully installed and working.</p><p><em>Thank you for using.</em></p></body></html>";
int WebServerImpl::serve_request(struct mg_connection *conn)
{
    if (IMPL(conn->server_param)->m_quit)
        return MG_FALSE;

    if (!strcmp(conn->uri, "/") || is_index(conn->uri+1)) {
        mg_send_data(conn, html_index, strlen(html_index));
        return MG_TRUE;
    }

    return MG_FALSE;
}

int WebServerImpl::serve_auth(struct mg_connection *conn)
{
    return MG_TRUE;
}

bool WebServerImpl::is_index(const char *uri)
{
    const static char *candinates =
        "index.html,index.htm,index.shtml,index.cgi,index.php";
    vector<string> vec(split(candinates, ","));
    FOR_VECTOR_ITERATOR(string, vec, it) {
        if ((*it) == uri) return true;
    }
    return false;
}

void *WebServerImpl::serve(void *param)
{
    ServeParam *sp = (ServeParam *) param;
    while (!IMPL(sp->user)->m_quit) {
        mg_poll_server(sp->server, 1000);
    }
    return NULL;
}

int WebServerImpl::send_response(struct mg_connection *conn,
                                 const char *code_desc, const char *content_type, int content_length,
                                 bool close_connection, uint8_t *content)
{
    char buff[4096];
    int n;
    n = snprintf(buff, sizeof(buff),
                 "HTTP/1.1 %s\r\n%sContent-Type:%s\r\nContent-Length:%d\r\n\r\n",
                 code_desc, close_connection ? "Connection:close\r\n" : "", content_type, content_length);
    int ret = mg_write(conn, buff, n);
    if (ret && content_length) {
        ret = mg_write(conn, content, content_length);
    }
    if (!ret) {
        LOGE("send_response() failed");
        return -1;
    }
    return 0;
}

/////////////////////////////////////////////////////////////

WebServer::WebServer(Config *conf)
{
    m_impl = new WebServerImpl(conf);
}

WebServer::~WebServer()
{
    WebServerImpl *trash = IMPL(m_impl);
    trash->stop();
    SAFE_DELETE(trash);
}

int WebServer::start(int listen_port, int server_threads)
{
    return IMPL(m_impl)->start(listen_port, server_threads);
}

int WebServer::stop()
{
    return IMPL(m_impl)->stop();
}

int WebServer::send_response(struct mg_connection *conn, const char *code_desc,
                             const char *content_type, int content_length,
                             bool close_connection, uint8_t *content)
{
    return WebServerImpl::send_response(conn, code_desc,
                                        content_type, content_length,
                                        close_connection, content);
}

}
