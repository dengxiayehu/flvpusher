#include "xcurl.h"

#include <memory>
#include <algorithm>

#include "xlog.h"

#define IMPL(x) ((CurlImpl *) (x))

//#define XDEBUG

using namespace xutil;
using namespace std;

namespace xcurl {

class CurlImpl {
public:
  CurlImpl();
  ~CurlImpl();

  int perform(vector<Curl::request *> reqvec);

  static int init(long flags = CURL_GLOBAL_DEFAULT);
  static void cleanup();
  static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *data);

private:
  struct conn_info;

  struct glob_info {
    CURLM *multi;
    int still_running;
    vector<conn_info *> connvec;

    glob_info();
    ~glob_info();

    int perform();
    void cleanup();
  };

  struct conn_info {
    CURL *easy;
    Curl::request *req;
    glob_info *glob;
    char error[CURL_ERROR_SIZE];
    bool trace_ascii;

    conn_info();
    ~conn_info();

    int setup(Curl::request *req_, glob_info *glob_);
    int perform();
    void cleanup();

    static int trace(CURL *handle, curl_infotype type,
                     char *data, size_t size, void *userp);
    static void dump(const char *text, uint8_t *ptr, size_t size, char nohex);
    static int progress(void *p, double dltotal, double dlnow,
                        double ult, double uln);
  };

private:
  DISALLOW_COPY_AND_ASSIGN(CurlImpl);
  RecursiveMutex m_mutex;
  glob_info m_glob;
};

Curl::request *Curl::request::build(request_type type, const char *url,
                                    size_t (*write_cb)(void *, size_t, size_t, void *), void *write_data,
                                    long timeout, const char *range, bool verbose, bool trace_ascii,
                                    bool no_signal,
                                    bool follow_location, long max_redirs,
                                    bool progress,
                                    size_t (*read_cb)(void *, size_t, size_t, void *), void *read_data,
                                    const char *post_fields, long post_fields_size, char *cookie_file,
                                    long low_speed_limit, long low_speed_time,
                                    const char *user_agent)
{
  request *req = new request;
  memset(req, 0, sizeof(request));
  req->type = type;
  req->url = strdup_(url);
  req->write_cb = write_cb;
  req->write_data = write_data;
  req->timeout = timeout;
  req->range = strdup_(range);
  req->verbose = verbose;
  req->trace_ascii = trace_ascii;
  req->no_signal = no_signal;
  req->follow_location = follow_location;
  req->max_redirs = max_redirs;
  req->progress = progress;
  req->read_cb = read_cb;
  req->read_data = read_data;
  req->post_fields = strdup_(post_fields);
  req->post_field_size = post_fields_size;
  req->cookie_file = strdup_(cookie_file);
  req->low_speed_limit = low_speed_limit;
  req->low_speed_time = low_speed_time;
  req->user_agent = strdup_(user_agent);

  req->effective_url = NULL;
  req->response_code = -1;
  req->speed_download = 0;
  req->total_time = 0;
  return req;
}

void Curl::request::recycle(request **req)
{
  if (!req || !(*req)) return;
  SAFE_FREE((*req)->url);
  SAFE_FREE((*req)->range);
  SAFE_FREE((*req)->post_fields);
  SAFE_FREE((*req)->cookie_file);
  SAFE_FREE((*req)->effective_url);
  SAFE_FREE((*req)->user_agent);
  SAFE_DELETE((*req));
}

Curl::Curl()
{
  m_impl = new CurlImpl();
}

Curl::~Curl()
{
  CurlImpl *trash = IMPL(m_impl);
  SAFE_DELETE(trash);
}

int Curl::perform(request *req, ...)
{
  vector<Curl::request *> reqvec;
  reqvec.push_back(req);
  va_list ap;
  va_start(ap, req);
  while ((req = va_arg(ap, Curl::request *)))
    reqvec.push_back(req);
  va_end(ap);
  return IMPL(m_impl)->perform(reqvec);
}

int Curl::perform(vector<Curl::request *> reqvec)
{
  return IMPL(m_impl)->perform(reqvec);
}

int Curl::init(long flags)
{
  return CurlImpl::init(flags);
}

size_t Curl::write_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
  return CurlImpl::write_cb(ptr, size, nmemb, data);
}

void Curl::cleanup()
{
  return CurlImpl::cleanup();
}

/////////////////////////////////////////////////////////////

CurlImpl::CurlImpl()
{
}

CurlImpl::~CurlImpl()
{
}

CurlImpl::glob_info::glob_info() :
  still_running(0)
{
  multi = curl_multi_init();
  if (!multi) {
    LOGE("curl_multi_init() failed");
    assert(0);
  }
}

CurlImpl::glob_info::~glob_info()
{
  cleanup();
}

int CurlImpl::glob_info::perform()
{
  CURLMcode mc;

  do {
    mc = curl_multi_perform(multi, &still_running);
  } while (mc == CURLM_CALL_MULTI_PERFORM);
  if (mc != CURLM_OK) {
    LOGE("curl_multi_perform() failed:%s",
         curl_multi_strerror(mc));
    goto bail;
  }

  do {
    struct timeval timeout = { 1, 0 };
    int rc = 0;

    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    int maxfd = -1;

    long curl_timeo = -1;

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    if ((mc = curl_multi_timeout(multi, &curl_timeo)) != CURLM_OK) {
      LOGE("curl_multi_timeout() failed: %s", curl_multi_strerror(mc));
      goto bail;
    }
    if (curl_timeo >= 0) {
      timeout.tv_sec = curl_timeo / 1000;
      if (timeout.tv_sec > 1)
        timeout.tv_sec = 1;
      else
        timeout.tv_usec = (curl_timeo % 1000) * 1000;
    }

    mc = curl_multi_fdset(multi, &fdread, &fdwrite, &fdexcep, &maxfd);
    if (mc != CURLM_OK) {
      LOGE("curl_multi_fdset() failed: %s", curl_multi_strerror(mc));
      goto bail;
    }

    if (-1 == maxfd) sleep_(100);
    else rc = select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);
    switch (rc) {
      case -1: LOGE("select() failed: %s", ERRNOMSG); goto bail;
      case 0:
      default:
        do {
          mc = curl_multi_perform(multi, &still_running);
        } while (mc == CURLM_CALL_MULTI_PERFORM);
        if (mc != CURLM_OK) {
          LOGE("curl_multi_perform() failed:%s",
               curl_multi_strerror(mc));
          goto bail;
        }
        break;
    }
  } while (still_running);

  BEGIN
  CURLMsg *msg;
  int msgs_left;
  int transfers = connvec.size();
  while ((msg = curl_multi_info_read(multi, &msgs_left))) {
    if (msg->msg == CURLMSG_DONE) {
      FOR_VECTOR_ITERATOR(conn_info *, connvec, it) {
        conn_info *conn = NULL;
        curl_easy_getinfo((*it)->easy, CURLINFO_PRIVATE, &conn);
        if (*it == conn && conn->easy == msg->easy_handle) {
          char *eff_url = NULL;
          curl_easy_getinfo((*it)->easy, CURLINFO_EFFECTIVE_URL, &eff_url);
          conn->req->effective_url = strdup_(eff_url);
          curl_easy_getinfo(conn->easy, CURLINFO_RESPONSE_CODE, &conn->req->response_code);
          curl_easy_getinfo(conn->easy, CURLINFO_SPEED_DOWNLOAD, &conn->req->speed_download);
          curl_easy_getinfo(conn->easy, CURLINFO_TOTAL_TIME, &conn->req->total_time);
#ifdef XDEBUG
          LOGD("easy(%p) DONE: (url=\"%s\", eff_url=\"%s\", response_code=%d, speed_download=%0.3f kbytes/sec, total_time=%0.3f sec) ==> (%d) %s",
               conn->easy, conn->req->url, conn->req->effective_url, conn->req->response_code,
               conn->req->speed_download, conn->req->total_time,
               msg->data.result, conn->error);
#endif
          --transfers;
          break;
        }
      }
    }
  }
  if (!transfers) {
    while (!connvec.empty())
      delete (connvec[0]);
  } else {
    LOGE("multi(%p) has remaining easy handle(#%d)",
         multi, transfers);
    goto bail;
  }
  END
  return 0;

bail:
  cleanup();
  return -1;
}

void CurlImpl::glob_info::cleanup()
{
  if (multi) {
    while (!connvec.empty())
      delete (connvec[0]);
    curl_multi_cleanup(multi);
    connvec.clear();
    multi = NULL;
  }
}

CurlImpl::conn_info::conn_info() :
  easy(NULL), req(NULL), glob(NULL), trace_ascii(true)
{
  memset(error, 0, sizeof(error));
}

CurlImpl::conn_info::~conn_info()
{
  cleanup();
}

int CurlImpl::conn_info::setup(Curl::request *req_, glob_info *glob_)
{
  req = req_;
  trace_ascii = req_->trace_ascii;

  easy = curl_easy_init();
  if (!easy) {
    LOGE("curl_easy_init() failed");
    goto bail;
  }
  curl_easy_setopt(easy, CURLOPT_URL, req->url);
  switch (req->type) {
    case Curl::GET:
      curl_easy_setopt(easy, CURLOPT_HTTPGET, 1L);
      break;
    case Curl::POST:
      curl_easy_setopt(easy, CURLOPT_HTTPPOST, 1L);
      if (req->post_fields)
        curl_easy_setopt(easy, CURLOPT_POSTFIELDS, req->post_fields);
      if (req->post_field_size > 0)
        curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE, req->post_field_size);
      if (req->cookie_file)
        curl_easy_setopt(easy, CURLOPT_COOKIEFILE, req->cookie_file);
      break;
    case Curl::OPTIONS:
      curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, "OPTIONS");
      break;
    default:
      LOGE("Not supported request type: %d", req->type);
      goto bail;
  }
  if (req->write_cb)
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, req->write_cb);
  if (req->write_data)
    curl_easy_setopt(easy, CURLOPT_WRITEDATA, req->write_data);
  if (req->read_cb)
    curl_easy_setopt(easy, CURLOPT_READFUNCTION, req->read_cb);
  if (req->read_data)
    curl_easy_setopt(easy, CURLOPT_READDATA, req->read_data);
  if (req->timeout > 0)
    curl_easy_setopt(easy, CURLOPT_TIMEOUT, req->timeout);
  if (req->range)
    curl_easy_setopt(easy, CURLOPT_RANGE, req->range);
  if (req->verbose) {
    curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
    if (!req->trace_ascii) {
      curl_easy_setopt(easy, CURLOPT_DEBUGFUNCTION, conn_info::trace);
      curl_easy_setopt(easy, CURLOPT_DEBUGDATA, this);
    }
  }
  if (req->progress) {
    curl_easy_setopt(easy, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(easy, CURLOPT_PROGRESSFUNCTION, conn_info::progress);
    curl_easy_setopt(easy, CURLOPT_PROGRESSDATA, this);
  }
  if (req->follow_location)
    curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 1L);
  if (req->max_redirs > 0)
    curl_easy_setopt(easy, CURLOPT_MAXREDIRS, req->max_redirs);
  if (req->no_signal)
    curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
  if (req->low_speed_limit > 0)
    curl_easy_setopt(easy, CURLOPT_LOW_SPEED_LIMIT, req->low_speed_limit);
  if (req->low_speed_time > 0)
    curl_easy_setopt(easy, CURLOPT_LOW_SPEED_TIME, req->low_speed_time);
  if (req->user_agent && strlen(req->user_agent))
    curl_easy_setopt(easy, CURLOPT_USERAGENT, req->user_agent);
  curl_easy_setopt(easy, CURLOPT_ERRORBUFFER, error);
  curl_easy_setopt(easy, CURLOPT_PRIVATE, this);

  if (glob_) {
    if (!glob_->multi) {
      LOGE("multi handle already cleaned up");
      goto bail;
    }
    CURLMcode mc = curl_multi_add_handle(glob_->multi, easy);
    if (mc != CURLM_OK) {
      LOGE("curl_multi_add_handle(%p) failed: %s",
           easy, curl_multi_strerror(mc));
      goto bail;
    }
    glob = glob_;
#ifdef XDEBUG
    LOGD("Adding easy %p to multi %p (%s)", easy, glob->multi, req->url);
#endif
    glob->connvec.push_back(this);
  }
  return 0;

bail:
  cleanup();
  return -1;
}

int CurlImpl::conn_info::perform()
{
  CURLcode res = curl_easy_perform(easy);
  if (res != CURLE_OK) {
    LOGE("curl_easy_perform() failed: %s",
         curl_easy_strerror(res));
    cleanup();
    return -1;
  }
  char *eff_url = NULL;
  curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &eff_url);
  req->effective_url = strdup_(eff_url);
  curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &req->response_code);
  curl_easy_getinfo(easy, CURLINFO_SPEED_DOWNLOAD, &req->speed_download);
  curl_easy_getinfo(easy, CURLINFO_TOTAL_TIME, &req->total_time);
#ifdef XDEBUG
  LOGD("easy(%p) DONE: (url=\"%s\", eff_url=\"%s\", response_code=%d, speed_download=%0.3f kbytes/sec, total_time=%0.3f sec)",
       easy, req->url, req->effective_url, req->response_code,
       req->speed_download, req->total_time);
#endif
  return 0;
}

void CurlImpl::conn_info::cleanup()
{
  if (easy) {
    if (glob) {
      vector<conn_info *>::iterator it =
        find(glob->connvec.begin(), glob->connvec.end(), this);
      if (it != glob->connvec.end()) {
        curl_multi_remove_handle(glob->multi, easy);
        glob->connvec.erase(it);
      }
      glob = NULL;
    }

    req = NULL;

    curl_easy_cleanup(easy);
    easy = NULL;
  }
}

int CurlImpl::conn_info::trace(CURL *handle, curl_infotype type,
                               char *data, size_t size, void *userp)
{
  conn_info *conn = (conn_info *) userp;
  const char *text = NULL;
  UNUSED(handle);
  switch (type) {
    case CURLINFO_TEXT:
      LOGD("\n== Info: %s", data);
    default:
      return 0;

    case CURLINFO_HEADER_OUT:
      text = "=> Send header";
      break;
    case CURLINFO_DATA_OUT:
      text = "=> Send data";
      break;
    case CURLINFO_SSL_DATA_OUT:
      text = "=> Send SSL data";
      break;
    case CURLINFO_HEADER_IN:
      text = "<= Recv header";
      break;
    case CURLINFO_DATA_IN:
      text = "<= Recv data";
      break;
    case CURLINFO_SSL_DATA_IN:
      text = "<= Recv SSL data";
      break;
  }

  dump(text, (uint8_t *) data, size, conn->trace_ascii);
  return 0;
}

void CurlImpl::conn_info::dump(const char *text, uint8_t *ptr, size_t size, char nohex)
{
  unsigned int width = 0x10;
  auto_ptr<IOBuffer> iobuf(new IOBuffer);

  if (nohex)
    width = 0x40;

  iobuf->read_from_string("\n%s, %10.10ld bytes (0x%8.8lx)\n",
                          text, (long) size, (long) size);

  for (size_t i = 0; i < size; i += width) {
    iobuf->read_from_string("%4.4lx: ", (long) i);

    if (!nohex) {
      for (size_t c = 0; c < width; ++c) {
        if (i + c < size)
          iobuf->read_from_string("%02x ", ptr[i+c]);
        else
          iobuf->read_from_string("   ");
      }
    }

    for (size_t c = 0; (c < width) && (i+c < size); ++c) {
      if (nohex && (i+c+1 < size) && ptr[i+c]==0x0D && ptr[i+c+1]==0x0A) {
        i += (c+2-width);
        break;
      }
      iobuf->read_from_string("%c",
          (ptr[i+c]>=0x20)&&(ptr[i+c]<0x80)?ptr[i+c]:'.');
      if (nohex && (i+c+2 < size) && ptr[i+c+1]==0x0D && ptr[i+c+2]==0x0A) {
        i += (c+3-width);
        break;
      }
    }
    iobuf->read_from_string("\n");
  }

  (GETIBPOINTER(*iobuf))[GETAVAILABLEBYTESCOUNT(*iobuf)] = '\0';
  LOGD("%s", (char *) GETIBPOINTER(*iobuf));
}

int CurlImpl::conn_info::progress(void *p, double dltotal, double dlnow,
    double ult, double uln)
{
#ifdef XDEBUG
  conn_info *conn = (conn_info *) p;
  UNUSED(ult);
  UNUSED(uln);
  LOGD("Progress: %s (%g/%g)", conn->req->url, dlnow, dltotal);
#endif
  return 0;
}

int CurlImpl::perform(vector<Curl::request *> reqvec)
{
  if (reqvec.empty()) {
    LOGW("No request passed to perform() ?? (ignored)");
    return 0;
  } else if (reqvec.size() == 1) {
    auto_ptr<conn_info> conn(new conn_info);
    if (conn->setup(reqvec[0], NULL) < 0) {
      LOGE("conn->setup() failed");
      return -1;
    }
    if (conn->perform() < 0) {
      LOGE("easy perform failed");
      return -1;
    }
    return 0;
  } else {
    AutoLock _l(m_mutex);
    FOR_VECTOR_ITERATOR(Curl::request *, reqvec, it) {
      conn_info *conn = new conn_info;
      if (conn->setup(*it, &m_glob) < 0) {
        LOGE("conn->setup() failed");
        SAFE_DELETE(conn);
        return -1;
      }
    }
    if (m_glob.perform() < 0) {
      LOGE("multi perform failed");
      return -1;
    }
    return 0;
  }
}

int CurlImpl::init(long flags)
{
  CURLcode cc = curl_global_init(flags);
  if (cc != CURLE_OK) {
    LOGE("curl_global_init() failed: %s",
         curl_easy_strerror(cc));
    return -1;
  }
  return 0;
}

void CurlImpl::cleanup()
{
  curl_global_cleanup();
}

size_t CurlImpl::write_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
  IOBuffer *iobuf = (IOBuffer *) data;
  iobuf->read_from_buffer((const uint8_t *) ptr, size * nmemb);
  return size * nmemb;
}

}
