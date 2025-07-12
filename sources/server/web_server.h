#ifndef _WEB_SERVER_H_
#define _WEB_SERVER_H_

#include <xconfig.h>

struct mg_connection;

namespace flvpusher {

class WebServer {
public:
    explicit WebServer(xconfig::Config* conf);
    ~WebServer();

    int start(int listen_port, int server_threads);
    int pulse();
    int stop();

    static int send_response(struct mg_connection* conn, const char* code_desc, const char* content_type = "text/plain",
                             int content_length = 0, bool close_connection = true, uint8_t* content = NULL);

private:
    void* m_impl;
    DISALLOW_COPY_AND_ASSIGN(WebServer);
};

}  // namespace flvpusher

#endif /* end of _WEB_SERVER_H_ */
