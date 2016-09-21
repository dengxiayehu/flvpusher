#include "xutil.h"

#include <string>
#include <iterator>
#include <sstream>

#include <cstdlib>
#include <libgen.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#include "xlog.h"
#include "xfile.h"

namespace xutil {

std::string sprintf_(const char *fmt, ...)
{
  char buf[MaxLine*2];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf)-1, fmt, ap);
  va_end(ap);
  return std::string(buf);
}

bool is_valid_ip(const char *ip)
{
  if (inet_addr(ip) != INADDR_NONE) {
    return true;
  }

  LOGE("inet_addr failed: %s", ERRNOMSG);
  return false;
}

std::vector<std::string> split(const std::string str, const char *delim)
{
  // Make a copy of str, for the following strtok will modify it
  char *s = strdup(STR(str));
  std::vector<std::string> result;
  const char *p = strtok(s, delim);
  while (p) {
    result.push_back(p);
    p = strtok(NULL, delim);
  }
  SAFE_FREE(s);
  return result;
}

ssize_t writen(int fd, const void *buf, size_t n)
{
  size_t to_write;
  ssize_t nwritten;
  const char *ptr = NULL;

  for (ptr = static_cast<const char *>(buf), to_write = n;
       to_write > 0;
       ptr += nwritten, to_write -= nwritten) {
    nwritten = write(fd, ptr, to_write);
    if (-1 == nwritten) {
      if (EINTR == errno)
        continue;
      return -1;
    }
  }

  return ptr - static_cast<const char *>(buf);
}

ssize_t readn(int fd, void *buf, size_t n)
{
  size_t to_read;
  ssize_t nread;
  char *ptr = NULL;

  for (ptr = static_cast<char *>(buf), to_read = n;
       to_read > 0;
       ptr += nread, to_read -= nread) {
    if ((nread = read(fd, ptr, to_read)) < 0) {
      if (EINTR == errno)
        nread = 0;
      else
        return -1;
    } else if (0 == nread)
      break;
  }

  return (n - to_read);
}

char *skip_blank(char *p)
{
  while (*p && isspace(*p))
    ++p;
  return p;
}

uint64_t get_time_now()
{
  struct timeval tv;
  ::gettimeofday(&tv, NULL);
  return tv.tv_sec * 1000LL + tv.tv_usec / 1000LL;
}

char *strcasechr(const char *s, int c)
{
  const char *p = strchr(s, toupper(c));
  if (!p) p = strchr(s, tolower(c));
  return const_cast<char *>(p);
}

bool end_with(const std::string &str, const std::string &sub)
{
  return (str.length() >= sub.length()) && (str.rfind(STR(sub)) == str.size()-sub.size());
}

bool start_with(const std::string &str, const std::string &sub)
{
  return (str.length() >= sub.length()) && (str.find(STR(sub)) == 0);
}

int system_(const char *fmt, ...)
{
  char cmd[4096];

  va_list ap;
  va_start(ap, fmt);
  vsnprintf(cmd, sizeof(cmd)-1, fmt, ap);
  va_end(ap);

  sighandler_t hdl = signal(SIGCHLD, SIG_DFL);
  int ret = system(cmd);
  signal(SIGCHLD, hdl);
  return ret;
}

bool exec_get_int(const char *cmd, int *val)
{
  char buff[128];

  if (exec_get_str(cmd, buff, sizeof(buff))) {
    *val = atoi(buff);
    return true;
  }

  return false;
}

bool exec_get_str(const char *cmd, char buff[], size_t len)
{
  FILE *fp = NULL;
  char line[4096];
  size_t offset = 0;
  bool ret = true;
  void (*orig_hdl)(int);

  if ((orig_hdl = signal(SIGCHLD, SIG_IGN)) == SIG_ERR) {
    LOGE("ignore SIGCHLD before popen failed: %s", ERRNOMSG);
    return false;
  }

  fp = popen(cmd, "r");
  if (!fp) {
    fprintf(stderr, "popen failed: %s\n", ERRNOMSG);
    ret = false;
    goto out;
  }

  while (fgets(line, sizeof(line), fp))
    offset += snprintf(buff + offset, len - offset, "%s", line);

  if (ferror(fp)) {
    fprintf(stderr, "fgets failed: %s\n", ERRNOMSG);
    ret = false;
    goto out;
  }

  if (offset)
    buff[strlen(buff) - 1] = '\0';

out:
  if (fp) pclose(fp);

  if (orig_hdl != SIG_ERR) {
    if (signal(SIGCHLD, orig_hdl) == SIG_ERR) {
      LOGE("restore SIGCHLD after popen failed: %s",
           ERRNOMSG);
      ret = false;
    }
  }

  return ret;
}

std::string uuid()
{
  char buff[128];

  CHECK_EXPR_EXEC_RETVAL(!exec_get_str("uuidgen -t", buff, sizeof(buff)),
                         LOGE("try to generate uuid failed"),
                         sprintf_("%d", rand()));

  return std::string(buff);
}

std::string to_upper_str(const char *str)
{
  CHECK_EXPR_EXEC_RETVAL(!str,
                         LOGE("Null parm passed"),
                         std::string("NULL"));

  std::string s(str);
  for (std::string::size_type i = 0; i < s.size(); ++i)
    s[i] = toupper(s[i]);
  return s;
}

std::string to_lower_str(const char *str)
{
  CHECK_EXPR_EXEC_RETVAL(!str,
                         LOGE("Null parm passed"),
                         std::string("NULL"));

  std::string s(str);
  for (std::string::size_type i = 0; i < s.size(); ++i)
    s[i] = tolower(s[i]);
  return s;
}

std::string time_label()
{
  struct timeval tv;

  if (-1 == gettimeofday(&tv, NULL)) {
    fprintf(stderr, "gettimeofday failed: %s\n", ERRNOMSG);
    return "Unknown";
  } else {
    char time_buf[128];
    struct tm *ptm = localtime(&tv.tv_sec);
    snprintf(time_buf, sizeof(time_buf),
             "%04d-%02d-%02d-%02d:%02d:%02d.%03ld ",
             ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
             ptm->tm_hour, ptm->tm_min, ptm->tm_sec,
             tv.tv_usec/1000);
    return time_buf;
  }
}

byte *put_be16(byte *output, uint16_t val)
{        
  output[1] = val & 0xff;
  output[0] = val >> 8;
  return output + 2;
}

byte *put_be24(byte *output, uint32_t val)
{
  output[2] = val & 0xff;
  output[1] = val >> 8;
  output[0] = val >> 16;
  return output + 3;
}

byte *put_be32(byte *output, uint32_t val)
{
  output[3] = val & 0xff;
  output[2] = val >> 8;
  output[1] = val >> 16;
  output[0] = val >> 24;
  return output + 4;
}

byte *put_be64(byte *output, uint64_t val)
{   
  output = put_be32(output, val >> 32);
  output = put_be32(output, (uint32_t) val); 
  return output;
}

const std::string dirname_(const std::string &path)
{
  char *path_ = strdup(STR(path));
  if (!path_) {
    LOGE("strdup() failed: %s", ERRNOMSG);
    return std::string("Unknown");
  }
  const std::string retval(::dirname(path_));
  SAFE_FREE(path_);
  return retval;
}

const std::string basename_(const std::string &path)
{
  char *path_ = strdup(STR(path));
  if (!path_) {
    LOGE("strdup() failed: %s", ERRNOMSG);
    return std::string("Unknown");
  }
  const std::string retval(::basename(path_));
  SAFE_FREE(path_);
  return retval;
}

bool is_dir(const std::string &path)
{
  struct stat buf;
  if (!::stat(STR(path), &buf)) {
    if (S_ISDIR(buf.st_mode))
      return true;
  }
  return false;
}

bool is_file(const std::string &path)
{
  struct stat buf;
  if (!::stat(STR(path), &buf)) {
    if (S_ISREG(buf.st_mode))
      return true;
  }
  return false;
}

static char base64_decode_table[256];
static void init_base64_decode_table()
{
  int i;
  for (i = 0; i < 256; ++i) base64_decode_table[i] = (char) 0x80;
  for (i = 'A'; i <= 'Z'; ++i) base64_decode_table[i] = 0 + (i - 'A');
  for (i = 'a'; i <= 'z'; ++i) base64_decode_table[i] = 26 + (i - 'a');
  for (i = '0'; i <= '9'; ++i) base64_decode_table[i] = 52 + (i - '0');
  base64_decode_table[(unsigned char)'+'] = 62;
  base64_decode_table[(unsigned char)'/'] = 63;
  base64_decode_table[(unsigned char)'='] = 0;
}

unsigned char *base64_decode(const char *in, unsigned in_size,
                             unsigned &result_size, bool trim_trailing_zeros)
{
  static bool have_initialized_base64_decode_table = false;
  if (!have_initialized_base64_decode_table) {
    init_base64_decode_table();
    have_initialized_base64_decode_table = true;
  }

  unsigned char *out = (unsigned char *) malloc(strlen(in) + 1);
  int k = 0;
  int padding_count = 0;
  const int j_max = in_size - 3;
  for (int j = 0; j < j_max; j += 4) {
    char in_tmp[4], out_tmp[4];
    for (int i = 0; i < 4; ++i) {
      in_tmp[i] = in[i+j];
      if (in_tmp[i] == '=') ++padding_count;
      out_tmp[i] = base64_decode_table[(unsigned char)in_tmp[i]];
      if ((out_tmp[i]&0x80) != 0) out_tmp[i] = 0;
    }

    out[k++] = (out_tmp[0]<<2) | (out_tmp[1]>>4);
    out[k++] = (out_tmp[1]<<4) | (out_tmp[2]>>2);
    out[k++] = (out_tmp[2]<<6) | (out_tmp[3]);
  }

  if (trim_trailing_zeros)
    while (padding_count > 0 && k > 0 && out[k-1] == '\0') { --k; --padding_count; }
  result_size = k;
  unsigned char* result = (unsigned char *) malloc(result_size);
  memmove(result, out, result_size);
  SAFE_FREE(out);
  return result;
}

static const char base64_char[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char *base64_encode(char const *orig_signed, unsigned orig_length)
{
  unsigned char const* orig = (unsigned char const*) orig_signed;
  if (orig == NULL) return NULL;

  unsigned const num_orig_24_bit_values = orig_length/3;
  bool have_padding = orig_length > num_orig_24_bit_values*3;
  bool have_padding2 = orig_length == num_orig_24_bit_values*3 + 2;
  unsigned const num_result_bytes = 4*(num_orig_24_bit_values + have_padding);
  char* result = (char *) malloc(num_result_bytes + 1);

  unsigned i;
  for (i = 0; i < num_orig_24_bit_values; ++i) {
    result[4*i+0] = base64_char[(orig[3*i]>>2)&0x3F];
    result[4*i+1] = base64_char[(((orig[3*i]&0x3)<<4) | (orig[3*i+1]>>4))&0x3F];
    result[4*i+2] = base64_char[((orig[3*i+1]<<2) | (orig[3*i+2]>>6))&0x3F];
    result[4*i+3] = base64_char[orig[3*i+2]&0x3F];
  }

  if (have_padding) {
    result[4*i+0] = base64_char[(orig[3*i]>>2)&0x3F];
    if (have_padding2) {
      result[4*i+1] = base64_char[(((orig[3*i]&0x3)<<4) | (orig[3*i+1]>>4))&0x3F];
      result[4*i+2] = base64_char[(orig[3*i+1]<<2)&0x3F];
    } else {
      result[4*i+1] = base64_char[((orig[3*i]&0x3)<<4)&0x3F];
      result[4*i+2] = '=';
    }
    result[4*i+3] = '=';
  }

  result[num_result_bytes] = '\0';
  return result;
}

bool is_base64_encoded(const char *str)
{
  unsigned int tmp_decoded_size;
  char *tmp_decoded = (char *) base64_decode(str, strlen(str), tmp_decoded_size);
  if (!tmp_decoded) return false;
  char *tmp_encoded = (char *) base64_encode(tmp_decoded, tmp_decoded_size);
  if (!tmp_encoded) { SAFE_FREE(tmp_decoded); return false; }
  bool retval = !strcmp(str, tmp_encoded);
  SAFE_FREE(tmp_decoded);
  SAFE_FREE(tmp_encoded);
  return retval;
}

void sleep_(uint64_t ms)
{
  usleep(ms * 1000);
}

void short_snap(uint64_t ms, volatile bool *quit, uint64_t granularity)
{
  for (unsigned i = 0, n = (unsigned) (ms / granularity); i < n && !*quit; ++i)
    sleep_(granularity);
  if (!*quit)
    sleep_(ms%granularity);
}

char *strdup_(const char *s)
{
  if (!s)
    return NULL;
  return strdup(s);
}

void rm_(const std::string &path)
{
  system_(STR(sprintf_("rm -rf \"%s\"", STR(path))));
}

int is_path_absolute(const char *path)
{
  return path && path[0] == '/';
}

TagType get_tag_mask(TagType tag)
{
  TagType result = 0xffffffffffffffffLL;
  for (int8_t i = 56; i >= 0; i -= 8) {
    if (((tag >> i)&0xff) == 0)
      break;
    result = result >> 8;
  }
  return ~result;
}

int scandir(void *opaque, const char *path,
            int (*cb)(void *, const char *))
{
  DIR *dir;
  struct dirent *dirent;
  int ret = 0;

  if (!path || !cb)
    return -1;

  dir = opendir(path);
  if (!dir) {
    LOGE("Open dir \"%s\" failed: %s\n",
         path, ERRNOMSG);
    return -1;
  }

  while (!ret &&
         (dirent = readdir(dir))) {
    if (!strcmp(dirent->d_name, ".") || !strcmp(dirent->d_name, ".."))
      continue;

    if (cb(opaque,
           STR(sprintf_("%s%c%s", path, DIRSEP, dirent->d_name))) < 0)
      ret = -1;
  }

  closedir(dir);
  return ret;
}

/////////////////////////////////////////////////////////////

Mutex::Mutex(MutexType typ)
{
  pthread_mutexattr_init(&m_attr);
  pthread_mutexattr_settype(&m_attr,
                            typ == NORMAL ? PTHREAD_MUTEX_NORMAL : PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&m_mutex, &m_attr);
}

Mutex::~Mutex()
{
  pthread_mutexattr_destroy(&m_attr);
  pthread_mutex_destroy(&m_mutex);
}

Condition::Condition(Mutex &m, ConditionType typ) :
  m_mutex(m)
{
  pthread_condattr_init(&m_cond_attr);
  pthread_condattr_setpshared(&m_cond_attr,
                              typ == PRIVATE ? PTHREAD_PROCESS_PRIVATE : PTHREAD_PROCESS_SHARED);
  pthread_cond_init(&m_cond, &m_cond_attr);
}

Condition::~Condition()
{
  pthread_condattr_destroy(&m_cond_attr);
  pthread_cond_destroy(&m_cond);
}

int Condition::wait()
{
  int errcode = pthread_cond_wait(&m_cond, &m_mutex.m_mutex);
  if (errcode != 0) {
    LOGE("pthread_cond_wait() failed: %s", strerror(errcode));
    return -1;
  }
  return 0;
}

int Condition::signal()
{
  int errcode = pthread_cond_signal(&m_cond);
  if (errcode != 0) {
    LOGE("pthread_cond_signal() failed: %s", strerror(errcode));
    return -1;
  }
  return 0;
}

int Condition::broadcast()
{
  int errcode = pthread_cond_broadcast(&m_cond);
  if (errcode != 0) {
    LOGE("pthread_cond_broadcast() failed: %s", strerror(errcode));
    return -1;
  }
  return 0;
}

/////////////////////////////////////////////////////////////

Signaler *Signaler::signaler = NULL;
RecursiveMutex Signaler::mutex;

status_t Signaler::install(sighandler_t hdl, ...)
{
  int signo;
  va_list ap;
  va_start(ap, hdl);
  while ((signo = va_arg(ap, int)) > 0 &&
      signo != SIGLIST_END) {
    sighandler_t sighdl = ::signal(signo, hdl);
    if (SIG_ERR == sighdl) {
      LOGE("signal for %s(%d) failed: %s",
           sys_siglist[signo], signo, ERRNOMSG);
      return ERR_SYS;
    } else {
      m_signo_hdl_map[signo] = sighdl;
    }
  }
  va_end(ap);
  return SUCCESS;
}

Signaler::~Signaler()
{
  FOR_MAP(m_signo_hdl_map, int, sighandler_t, it) {
    if (SIG_ERR == ::signal(it->first, it->second)) {
      LOGE("restore signal for %s(%d) failed: %s",
           sys_siglist[it->first], it->first, ERRNOMSG);
      continue;
    }

    // Restore signal-handler
    m_signo_hdl_map[it->first] = SIG_DFL;
  }
}

/////////////////////////////////////////////////////////////

Thread::Thread(bool detach) :
  m_tid(-1),
  m_detach(detach)
{
}

void *Thread::thread_router(void *arg)
{
  Thread *thrd = reinterpret_cast<Thread *>(arg);
  thrd->run();

  if (thrd->is_detach()) {
    SAFE_DELETE(thrd);
  }

  return NULL;
}

status_t Thread::join()
{
  if (m_detach) {
    LOGE("Try to join a detached thread");
    return ERR_LOGICAL;
  }

  int ret = pthread_join(m_tid, NULL);
  if (ret != 0) {
    LOGE("pthread_join failed: %s", ERRNOMSG);
    return ERR_SYS;
  }

  return SUCCESS;
}

bool Thread::is_alive() const
{
  if (m_tid < 0) {
    LOGE("Thread hasn't been started");
    return false;
  }

  int ret = pthread_kill(m_tid, 0);
  if (ret == ESRCH || ret == EINVAL) {
    return false;
  }
  return true;
}

/////////////////////////////////////////////////////////////

MemHolder::MemHolder()
{
  m_capacity  = 0;
  m_buf       = NULL;
}

MemHolder::~MemHolder()
{
  SAFE_FREE(m_buf);
}

void *MemHolder::alloc(uint32_t sz)
{
  if (!sz) {
    LOGW("!Alloc 0 byte space, logic attention");
    return m_buf;
  }

  if (sz > m_capacity) {
    m_capacity = sz + 1024; // Try to alloc a bit more

    // Alloc the new wanted space
    void *tmp = malloc(m_capacity);
    if (!tmp) {
      LOGE("MemHolder malloc for size(%u) failed: %s",
           m_capacity, ERRNOMSG);

      destroy();
      return NULL;
    }

    // Free the previous space
    SAFE_FREE(m_buf);

    // Assign the new memory
    m_buf = tmp;
  }

  return m_buf;
}

void *MemHolder::calloc(uint32_t sz)
{
  void *p = alloc(sz);
  if (!p) return p;
  bzero(p, sz);
  return p;
}

void MemHolder::destroy()
{
  SAFE_FREE(m_buf);
  m_capacity = 0;
}

/////////////////////////////////////////////////////////////

IOBuffer::IOBuffer() :
  buffer(NULL),
  size(0),
  published(0),
  consumed(0),
  min_chunk_size(4096)
{
}

IOBuffer::~IOBuffer()
{
  cleanup();
}

void IOBuffer::initialize(uint32_t expected)
{
  if (buffer || size || published || consumed) {
    LOGE("Invalid IOBuffer state(%p,%u,%u,%u)",
         buffer, size, published, consumed);
    return;
  }

  ensure_size(expected);
}

bool IOBuffer::ensure_size(uint32_t expected)
{
  if (published + expected <= size)
    return true;

  move_data();

  if (published + expected <= size)
    return true;

  if ((published + expected - size) < (size/3))
    expected = size + size/3 - published;

  if (expected < min_chunk_size)
    expected = min_chunk_size;

  uint8_t *temp_buff = new uint8_t[published + expected];
  if (buffer) {
    memcpy(temp_buff, buffer, published);
    SAFE_DELETEA(buffer);
  }
  buffer = temp_buff;

  size = published + expected;
  return true;
}

bool IOBuffer::move_data()
{
  if (published - consumed <= consumed) {
    memcpy(buffer, buffer + consumed, published - consumed);
    published = published - consumed;
    consumed = 0;
  }

  return true;
}

bool IOBuffer::read_from_buffer(const uint8_t *buffer_, const uint32_t size_)
{
  if (!ensure_size(size_))
    return false;
  memcpy(buffer+published, buffer_, size_);
  published += size_;
  return true;
}

void IOBuffer::read_from_input_buffer(IOBuffer *input_buffer, uint32_t start, uint32_t size_)
{
  read_from_buffer(GETIBPOINTER(*input_buffer) + start, size_);
}

bool IOBuffer::read_from_input_buffer(const IOBuffer &buffer_, uint32_t size_)
{
  if (!read_from_buffer(buffer_.buffer + buffer_.consumed, size_))
    return false;
  return true;
}

bool IOBuffer::read_from_string(std::string binary)
{
  if (!read_from_buffer((uint8_t *) binary.data(), (uint32_t) binary.length()))
    return false;
  return true;
}

bool IOBuffer::read_from_string(const char *fmt, ...)
{
  char buf[MaxLine*2];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof(buf)-1, fmt, ap);
  va_end(ap);
  return read_from_buffer((uint8_t *) buf, n);
}

void IOBuffer::read_from_byte(uint8_t byte)
{
  ensure_size(1);
  buffer[published++] = byte;
}

void IOBuffer::read_from_repeat(uint8_t byte, uint32_t size_)
{
  ensure_size(size_);
  memset(buffer+published, byte, size_);
  published += size_;
}

void IOBuffer::read_from_file(const std::string &path, const char *mode)
{
  xfile::File f;
  if (!f.open(path, mode))
    return;
  ensure_size(f.size());
  f.read_buffer(buffer+published, f.size());
  published += f.size();
}

bool IOBuffer::write_to_stdio(int fd, uint32_t size_, int &sent_amount)
{
  bool result = true;
  sent_amount = writen(fd, buffer + consumed,
                       size_ > published - consumed ? published - consumed : size_);
  if (sent_amount < 0) {
    LOGE("Unable to write %u bytes of data", size_);
    result = false;
  } else {
    consumed += sent_amount;
  }
  if (result)
    recycle();
  return result;
}

uint32_t IOBuffer::get_min_chunk_size()
{
  return min_chunk_size;
}

void IOBuffer::set_min_chunk_size(uint32_t min_chunk_size_)
{
  assert(min_chunk_size_ > 0 && min_chunk_size_ < 16 * 1024 * 1024);
  min_chunk_size = min_chunk_size_;
}

uint32_t IOBuffer::get_current_write_position()
{
  return published;
}

uint8_t *IOBuffer::get_pointer()
{
  return buffer;
}

bool IOBuffer::ignore(uint32_t size_)
{
  consumed += size_;
  recycle();
  return true;
}

bool IOBuffer::ignore_all()
{
  consumed = published;
  recycle();
  return true;
}

void IOBuffer::recycle()
{
  if (consumed != published)
    return;
  consumed = 0;
  published = 0;
}

void IOBuffer::cleanup()
{
  SAFE_DELETEA(buffer);
  size = 0;
  published = 0;
  consumed = 0;
}

std::string IOBuffer::dump_buffer(const uint8_t *buffer_, uint32_t length)
{
  IOBuffer tmp;
  tmp.read_from_buffer(buffer_, length);
  return tmp.to_string();
}

std::string IOBuffer::to_string(uint32_t start_index, uint32_t limit)
{
  using namespace std;
  string allowed_characters = " 1234567890-=qwertyuiop[]asdfghjkl;'\\`zxcvbnm";
  allowed_characters += ",./!@#$%^&*()_+QWERTYUIOP{}ASDFGHJKL:\"|~ZXCVBNM<>?";
  std::stringstream ss;
  ss << "size: " << size << endl;
  ss << "published: " << published << endl;
  ss << "consumed: " << consumed << endl;
  ss << sprintf_("Address: %p", buffer) << endl;
  string address = "";
  string part1 = "";
  string part2 = "";
  string hr = "";
  limit = (limit == 0) ? published : limit;
  for (uint32_t i = start_index; i < limit; i++) {
    if (((i % 16) == 0) && (i > 0)) {
      ss << address << "  " << part1 << " " << part2 << " " << hr << endl;
      part1 = "";
      part2 = "";
      hr = "";
    }
    address = sprintf_("%08u", i - (i % 16));

    if ((i % 16) < 8) {
      part1 += sprintf_("%02hhx", buffer[i]);
      part1 += " ";
    } else {
      part2 += sprintf_("%02hhx", buffer[i]);
      part2 += " ";
    }

    if (allowed_characters.find(buffer[i], 0) != string::npos)
      hr += buffer[i];
    else
      hr += '.';
  }

  if (part1 != "") {
    part1 += string(24 - part1.size(), ' ');
    part2 += string(24 - part2.size(), ' ');
    hr += string(16 - hr.size(), ' ');
    ss << address << "  " << part1 << " " << part2 << " " << hr << endl;
  }
  return ss.str();
}

IOBuffer::operator std::string()
{
  return to_string(0, 0);
}

/////////////////////////////////////////////////////////////

AutoFileLock::AutoFileLock(const std::string &flock_path, short l_type) :
                           m_flock_path(flock_path)
{
  // Make sure the l_type is correct
  assert(l_type == F_WRLCK || l_type == F_RDLCK);

  m_fd = open(STR(m_flock_path), O_RDWR|O_CREAT,
              S_IRWXU|S_IRWXG|S_IRWXO);
  if (m_fd < 0) {
    LOGE("Open file lock \"%s\" failed: %s",
         STR(m_flock_path), ERRNOMSG);
    return;
  }

  struct flock lock;
  lock.l_whence = SEEK_SET;
  lock.l_start = 0;
  lock.l_len = 0;
  lock.l_type = l_type;
  if (fcntl(m_fd, F_SETLK, &lock) < 0) {
    LOGE("Lock file \"%s\" failed: %s",
         STR(m_flock_path), ERRNOMSG);
    SAFE_CLOSE(m_fd);
    return;
  }
}

AutoFileLock::~AutoFileLock()
{
  if (m_fd >= 0) {
    struct flock lock;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    lock.l_type = F_UNLCK;
    if (fcntl(m_fd, F_SETLK, &lock) < 0) {
      LOGE("Unlock file \"%s\" failed: %s",
           STR(m_flock_path), ERRNOMSG);
    }
    SAFE_CLOSE(m_fd);
  }
}

/////////////////////////////////////////////////////////////

int tm_to_time(const struct tm *tm, Time *t)
{
  if (!tm || !t)
    return -1;

  t->year = tm->tm_year + 1900;
  t->mon = tm->tm_mon + 1;
  t->day = tm->tm_mday;
  t->hour = tm->tm_hour;
  t->min = tm->tm_min;
  t->sec = tm->tm_sec;
  return 0;
}

int time_to_tm(const Time *t, struct tm *tm)
{
  if (!t || !tm)
    return -1;

  tm->tm_year = t->year - 1900;
  tm->tm_mon = t->mon - 1;
  tm->tm_mday = t->day;
  tm->tm_hour = t->hour;
  tm->tm_min = t->min;
  tm->tm_sec = t->sec;
  tm->tm_isdst = 0;
  return 0;
}

int time_get(Time *t)
{
  time_t now;
  struct tm *tm, tmpbuf;

  time(&now);
  tm = localtime_r(&now, &tmpbuf);
  if (!tm)
    return -1;
  return tm_to_time(tm, t);
}

long time_gap(const Time *t1, const Time *t2)
{
  assert(t1 && t2);
  return time_mktime(t1) - time_mktime(t2);
}

time_t time_mktime(const Time *t)
{
  struct tm tmpbuf;

  if (time_to_tm(t, &tmpbuf) < 0)
    return 0;
  return mktime(&tmpbuf);
}

int time_copy(Time *dst, const Time *src)
{
  if (!dst || !src)
    return -1;

  memcpy(dst, src, sizeof(*dst));
  return 0;
}

}
