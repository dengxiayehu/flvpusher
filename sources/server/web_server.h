#ifndef _WEB_SERVER_H_
#define _WEB_SERVER_H_

#include <string>
#include <xconfig.h>

namespace flvpusher {

class WebServer {
public:
  WebServer(xconfig::Config *conf);
  ~WebServer();

  int start(int listen_port, int server_threads);
  int pulse();
  int stop();

  static int send_response(struct mg_connection *conn, const char *code_desc,
                           const char *content_type = "text/plain", int content_length = 0,
                           bool close_connection = true, uint8_t *content = NULL);

private:
  DISALLOW_COPY_AND_ASSIGN(WebServer);
  void *m_impl;
};

}

#endif /* end of _WEB_SERVER_H_ */
