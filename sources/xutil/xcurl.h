#ifndef _XCURL_H_
#define _XCURL_H_

#include <curl/curl.h>

#include "xutil.h"

namespace xcurl {

class Curl {
public:
  Curl();
  ~Curl();

  enum request_type { GET, POST, OPTIONS };
  struct request {
    // In
    request_type type;
    char *url;
    size_t (*write_cb)(void *ptr, size_t size, size_t nmemb, void *data);
    void *write_data;
    long timeout;
    char *range;
    bool verbose;
    bool trace_ascii;
    bool no_signal;
    bool follow_location;
    long max_redirs;
    bool progress;
    size_t (*read_cb)(void *ptr, size_t size, size_t nmemb, void *data);
    void *read_data;
    char *post_fields;
    long post_field_size;
    char *cookie_file;
    long low_speed_limit;
    long low_speed_time;
    char *user_agent;

    // Out
    char *effective_url;
    long response_code;
    double speed_download;;
    double total_time;

    static request *build(request_type type, const char *url,
                          size_t (*write_cb)(void *, size_t, size_t, void *) = NULL, void *write_data = NULL,
                          long timeout = -1, const char *range = NULL, bool verbose = true, bool trace_ascii = true,
                          bool no_signal = true,
                          bool follow_location = true, long max_redirs = -1,
                          bool progress = false,
                          size_t (*read_cb)(void *, size_t, size_t, void *) = NULL, void *read_data = NULL,
                          const char *post_fields = NULL, long post_field_size = -1, char *cookie_file = NULL,
                          long low_speed_limit = -1, long low_speed_time = -1,
                          const char *user_agent = "libcurl-agent/1.0");
    static void recycle(request **req);
  };
  int perform(request *req, ...);
  int perform(std::vector<Curl::request *> reqvec);

  static int init(long flags = CURL_GLOBAL_DEFAULT);
  static void cleanup();
  static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *data);

private:
  DISALLOW_COPY_AND_ASSIGN(Curl);
  void *m_impl;
};

}

#endif /* end of _XLIBCURL_H_ */
