#ifndef _XUTIL_H_
#define _XUTIL_H_

// Large file support
#define _FILE_OFFSET_BITS 64

#include "xtype.h"

#include <iostream>
#include <vector>
#include <list>
#include <map>
#include <set>

#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <cstring>
#include <cerrno>
#include <cassert>

#include <signal.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include "xutil_macros.h"

namespace xutil {

const static int MaxLine = 4098;

typedef enum {
  SUCCESS = 0,
  ERROR,
  ERR_INVALID_PARM,
  ERR_OUT_OF_RESOURCE,
  ERR_INTERNAL,
  ERR_LOGICAL,
  ERR_SYS,
  ERR_NOT_EXISTS,
  ERR_REMOTE,
  ERR_NOT_IMPLEMENTED,
  ERR_INPUT,
} status_t;

inline const char *xstrerror(status_t st)
{
  static const char *info[] = {
    "success",
    "error occurred",
    "invalid param",
    "internal error",
    "logical error",
    "system error",
    "not exists",
    "remote error",
    "not implemented",
    "error input"
  };

  return info[st];
}

#define ERRNOMSG strerror(errno)

/////////////////////////////////////////////////////////////

std::string sprintf_(const char *fmt, ...);

bool is_valid_ip(const char *ip);

std::vector<std::string> split(const std::string str, const char *delim);

std::string hostname_to_ip(const char *hostname);

ssize_t readn(int fd, void *buf, size_t n);
ssize_t writen(int fd, const void *buf, size_t n);

char *skip_blank(char *p);

uint64_t get_time_now();

char *strcasechr(const char *s, int c);
bool end_with(const std::string &str, const std::string &sub);
bool start_with(const std::string &str, const std::string &sub);

int system_(const char *fmt, ...);

bool exec_get_int(const char *cmd, int *val);
bool exec_get_str(const char *cmd, char buff[], size_t len);

std::string uuid();

std::string to_upper_str(const char *str);
std::string to_lower_str(const char *str);

std::string time_label();

byte *put_be16(byte *output, uint16_t val);
byte *put_be24(byte *output, uint32_t val);
byte *put_be32(byte *output, uint32_t val);
byte *put_be64(byte *output, uint64_t val);

const std::string dirname_(const std::string &path);
const std::string basename_(const std::string &path);

bool is_dir(const std::string &path);
bool is_file(const std::string &path);

unsigned char *base64_decode(const char *in, unsigned in_size,
                             unsigned &result_size, bool trim_trailing_zeros = true);

char *base64_encode(char const *orig_signed, unsigned orig_length);
bool is_base64_encoded(const char *str);

void sleep_(uint64_t ms);
void short_snap(uint64_t ms, volatile bool *quit, uint64_t granularity = 100);

char *strdup_(const char *s);

void rm_(const std::string &path);

int is_path_absolute(const char *path);

typedef uint64_t TagType;
#define TAG_KIND_OF(tag,kind) ((bool)(((tag)&get_tag_mask((kind)))==(kind)))
TagType get_tag_mask(TagType tag);

int scandir(void *opaque, const char *path,
            int (*cb)(void *, const char *));

/////////////////////////////////////////////////////////////

class Condition;

class Mutex {
  friend class Condition;
public:
  enum MutexType { NORMAL, RECURSIVE };

public:
  explicit Mutex(MutexType typ = NORMAL);
  ~Mutex();

  void lock() {
    pthread_mutex_lock(&m_mutex);
  }
  void unlock() {
    pthread_mutex_unlock(&m_mutex);
  }

private:
  pthread_mutex_t     m_mutex;
  pthread_mutexattr_t m_attr;
};

class RecursiveMutex : public Mutex {
public:
  RecursiveMutex() : Mutex(RECURSIVE) { }
};

class AutoLock {
public:
  explicit AutoLock(Mutex &l) : m_mutex(l) {
    m_mutex.lock();
  }

  ~AutoLock() {
    m_mutex.unlock();
  }

private:
  DISALLOW_COPY_AND_ASSIGN(AutoLock);

  Mutex &m_mutex;
};

class Condition {
public:
  enum ConditionType { PRIVATE, SHARED };
public:
  Condition(Mutex &m, ConditionType typ = PRIVATE);
  ~Condition();

  int wait();
  int signal();
  int broadcast();

private:
  pthread_cond_t m_cond;
  pthread_condattr_t m_cond_attr;
  Mutex &m_mutex;
};

/////////////////////////////////////////////////////////////

class Signaler {
public:
  enum { SIGLIST_END = -1 };
public:
  ~Signaler();

  status_t install(sighandler_t hdl, ...);

  static Signaler *get_instance() {
    if (!signaler) {
      AutoLock l(mutex);

      if (!signaler) {
        signaler = new Signaler();
      }
    }
    return signaler;
  }

private:
  DISALLOW_COPY_AND_ASSIGN(Signaler);

  Signaler() { }

private:
  static Signaler *signaler;
  static RecursiveMutex mutex;

  std::map<int, sighandler_t> m_signo_hdl_map;
};

/////////////////////////////////////////////////////////////

#define DECL_THREAD_ROUTINE(Class, func)  \
  class func##Thread : public xutil::Thread { \
    public: \
            func##Thread(Class *arg1, void *arg2, bool detach) \
    : xutil::Thread(detach), m_arg1(arg1), m_arg2(arg2) { \
      pthread_attr_t attr; \
      pthread_attr_init(&attr); \
      pthread_attr_setdetachstate(&attr, \
          m_detach ? PTHREAD_CREATE_DETACHED : PTHREAD_CREATE_JOINABLE); \
      pthread_create(&m_tid, &attr, Thread::thread_router, \
          reinterpret_cast<void *>(this)); \
      pthread_attr_destroy(&attr); \
    } \
    virtual ~func##Thread() { } \
    virtual void run() { m_arg1->func(m_arg2); } \
    private: \
             Class *m_arg1; \
    void *m_arg2; \
  }; \
friend class func##Thread; \
void *func(void *arg);

#define CREATE_THREAD_ROUTINE(func, arg, detach) \
  new func##Thread(this, reinterpret_cast<void *>(arg), detach)

#define JOIN_DELETE_THREAD(thrd) \
  if (thrd) { \
    thrd->join(); \
    SAFE_DELETE(thrd); \
  }

class Thread {
public:
  explicit Thread(bool detach = false);
  virtual ~Thread() { }

  status_t join();
  bool is_detach() const { return m_detach; }
  bool is_alive() const;
  pthread_t get_tid() const { return m_tid; }

  virtual void run() = 0;

protected:
  static void * thread_router(void *arg);

  pthread_t           m_tid;
  bool                m_detach;
};

/////////////////////////////////////////////////////////////

class MemHolder { 
public:
  MemHolder();
  ~MemHolder();

  void *alloc(uint32_t sz);
  void *calloc(uint32_t sz);
  void *get_buffer() const { return m_buf; }

  void  destroy();

private:
  uint32_t    m_capacity;
  void      * m_buf;
};

/////////////////////////////////////////////////////////////

#define GETAVAILABLEBYTESCOUNT(x) ((x).published - (x).consumed)
#define GETIBPOINTER(x) ((uint8_t *)((x).buffer + (x).consumed))

class IOBuffer {
public:
  uint8_t *buffer;
  uint32_t size;
  uint32_t published;
  uint32_t consumed;
  uint32_t min_chunk_size;

public:
  IOBuffer();
  virtual ~IOBuffer();

  void initialize(uint32_t expected);
  bool ensure_size(uint32_t expected);
  bool move_data();
  bool read_from_buffer(const uint8_t *buffer_, const uint32_t size_);
  void read_from_input_buffer(IOBuffer *input_buffer, uint32_t start, uint32_t size_);
  bool read_from_input_buffer(const IOBuffer &buffer_, uint32_t size_);
  bool read_from_string(std::string binary);
  bool read_from_string(const char *fmt, ...);
  void read_from_byte(uint8_t byte);
  void read_from_repeat(uint8_t byte, uint32_t size_);
  void read_from_file(const std::string &path, const char *mode = "r");
  bool write_to_stdio(int fd, uint32_t size_, int &sent_amount);
  uint32_t get_min_chunk_size();
  void set_min_chunk_size(uint32_t min_chunk_size_);
  uint32_t get_current_write_position();
  uint8_t *get_pointer();
  bool ignore(uint32_t size_);
  bool ignore_all();
  void recycle();
  static std::string dump_buffer(const uint8_t *buffer_, uint32_t length);
  std::string to_string(uint32_t start_index = 0, uint32_t limit = 0);
  operator std::string();

private:
  void cleanup();

private:
  DISALLOW_COPY_AND_ASSIGN(IOBuffer);
};

/////////////////////////////////////////////////////////////

class AutoFileLock {
public:
  AutoFileLock(const std::string &flock_path, short l_type = F_WRLCK);
  ~AutoFileLock();

private:
  int  m_fd;
  std::string m_flock_path;
};

/////////////////////////////////////////////////////////////

typedef struct Time {
  int year;
  int mon;
  int day;
  int hour;
  int min;
  int sec;
} Time;

int time_get(Time *t);
long time_gap(const Time *t1, const Time *t2);
time_t time_mktime(const Time *t);
int time_copy(Time *dst, const Time *src);
int tm_to_time(const struct tm *tm, Time *t);
int time_to_tm(const Time *t, struct tm *tm);

}

#endif /* end of _XUTIL_H_ */
