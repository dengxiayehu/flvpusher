#include "xlog.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <pthread.h>
#include <execinfo.h>
#include <cxxabi.h>
#include <cerrno>

#define COLOR_FORMAT_NONE           "\033[0m"
#define COLOR_FORMAT_LEVEL_WARN     "\033[33;1m"
#define COLOR_FORMAT_LEVEL_ERR      "\033[31;1m"
#define COLOR_FORMAT_LEVEL_INFO     "\033[37;0m"
#define COLOR_FORMAT_LEVEL_DEBUG    "\033[37;0m"
#define COLOR_FORMAT_LEVEL_LOG      "\033[37;0m"

#define DEBUG_GDB 0

using namespace xutil;

namespace xlog {

struct log_t {
  int fd;
  log_level lvl;
  int flgs;
  log_t *next;
};

static log_t *log;
static RecursiveMutex mutex;

static const char *color_level[] = {
  COLOR_FORMAT_LEVEL_DEBUG,
  COLOR_FORMAT_LEVEL_INFO,
  COLOR_FORMAT_LEVEL_WARN,
  COLOR_FORMAT_LEVEL_ERR
};

static bool _need_free_sigstack = false;

static int sig_crashes_setup();
static void sig_crashes_restore();
static void fault_handler_sigaction(int signum, siginfo_t * si, void *misc);
static int addr2line(int pid, const char *library, const char *addr, char *buffer);
static const char *demangle_using_addr2line(int pid, char *buffer, const char *symbol);
static const char *demangle(const char *symbol, char *buffer);
static int gettimestr(char *buf);

status_t log_add_dst(const char *logfile, log_level lvl, int flgs)
{
  AutoLock _l(mutex);

  int fd = open(logfile,
                O_WRONLY|O_CREAT|O_NOCTTY|(flgs&LOG_TRUNC?O_TRUNC:O_APPEND),
                0666);
  if (fd < 0) {
    fprintf(stderr, "Open \"%s\" failed: %s\n",
            logfile, ERRNOMSG);
    return ERR_SYS;
  }

  log_t *l = (log_t *) calloc(1, sizeof(log_t));
  if (!l) {
    fprintf(stderr, "calloc for log_t failed: %s\n",
            ERRNOMSG);
    close(fd);
    return ERR_SYS;
  }

  l->fd  = fd;
  l->lvl = lvl;
  l->flgs = flgs;

  // Link to global log list
  if (!log) {
    if (sig_crashes_setup() < 0) {
      fprintf(stderr, "sig_crashes_setup() failed");
      return ERR_SYS;
    }

    log = l;
  } else {
    l->next = log->next;
    log->next = l;
  }

  return SUCCESS;
}

int set_log_level(const char *lvlstr)
{
  if (!lvlstr) {
    return -1;
  }

  if (!strcasecmp(lvlstr, "DEBUG")) {
    xlog::set_log_level(xlog::DEBUG);
  } else if (!strcasecmp(lvlstr, "INFO")) {
    xlog::set_log_level(xlog::INFO);
  } else if (!strcasecmp(lvlstr, "WARN")) {
    xlog::set_log_level(xlog::WARN);
  } else if (!strcasecmp(lvlstr, "ERR")) {
    xlog::set_log_level(xlog::ERR);
  } else {
    LOGE("Invalid log level \"%s\"", lvlstr);
    return -1;
  }

  return 0;
}

int set_log_level(log_level lvl)
{
  AutoLock _l(mutex);

  for (log_t *l = log; l; l = l->next) {
    l->lvl = lvl;
  }

  return 0;
}

int log_print(const char *curfile, const int lineno, const log_level lvl,
              const char *fmt, ...)
{
  static const char *lvl_name[] = {"[DEBUG]", "[INFO]", "[WARN]", "[ERROR]"};

  AutoLock _l(mutex);

  for (log_t *l = log; l; l = l->next) {
    if (lvl < l->lvl) {
      // No need to log this line
      continue;
    }

    char time_buf[128] = {0};
    if (!(l->flgs&LOG_NODATE)) {
      gettimestr(time_buf);
    }

    char tid_buf[10] = {0};
    if (!(l->flgs&LOG_NOTID)) {
      snprintf(tid_buf, sizeof(tid_buf), "%ld ", gettid());
    }

    char buf[MaxLine];
    int ret = snprintf(buf, sizeof(buf), "%s%s%s[%s:%d] %s ",
                       color_level[lvl],
                       time_buf,
                       tid_buf,
                       STR(basename_(curfile)), lineno,
                       lvl_name[lvl]);

    va_list ap;
    va_start(ap, fmt);
    ret = vsnprintf(buf + ret, sizeof(buf) - ret, fmt, ap);
    va_end(ap);

    strcat(buf, COLOR_FORMAT_NONE);

    if (!(l->flgs&LOG_NOLF))
      strcat(buf, "\n");

    if (l->flgs&LOG_STDERR)
      fprintf(stderr, "%s", buf);

    if (writen(l->fd, buf, strlen(buf)) < 0) {
      fprintf(stderr, "Write log failed: %s (cont)\n",
              ERRNOMSG);
      // Fall through
    }
  }

  return SUCCESS;
}

status_t log_close()
{
  AutoLock _l(mutex);

  log_t *p = log, *q;
  while (p) {
    q = p->next;
    SAFE_CLOSE(p->fd);
    SAFE_FREE(p);
    p = q;
  }

  sig_crashes_restore();

  return SUCCESS;
}

const int k_exception_signals[] = {
  SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGBUS, -1
};

#define  SIGNAL_MAX     64
static const char *_signal[SIGNAL_MAX];
static int sig_crashes_setup()
{
  const unsigned int k_sig_stack_size = 40960;

  stack_t stack;

  struct sigaction action;

  unsigned int i;

  for (i = 0; i < SIGNAL_MAX; ++i) {
    _signal[i] = "UnKnown";
  }
  _signal[SIGSEGV] = "SIGSEGV"; _signal[SIGABRT] = "SIGABRT";
  _signal[SIGFPE]  = "SIGFPE";  _signal[SIGILL]  = "SIGILL";
  _signal[SIGBUS]  = "SIGBUS";  _signal[SIGQUIT] = "SIGQUIT";
  _signal[SIGPIPE] = "SIGPIPE";

  if (sigaltstack(NULL, &stack) == -1 || !stack.ss_sp ||
      stack.ss_size < k_sig_stack_size) {
    memset(&stack, 0, sizeof(stack));
    stack.ss_sp = malloc(k_sig_stack_size);
    stack.ss_size = k_sig_stack_size;

    if (sigaltstack(&stack, NULL) == -1) {
      SAFE_FREE(stack.ss_sp);
      return -1;
    }

    _need_free_sigstack = true;
  }

  memset(&action, 0, sizeof(action));

  sigemptyset(&action.sa_mask);
#ifdef SIGHUP
  sigaddset(&action.sa_mask, SIGHUP);
#endif
#ifdef SIGINT
  sigaddset(&action.sa_mask, SIGINT);
#endif
#ifdef SIGQUIT
  sigaddset(&action.sa_mask, SIGQUIT);
#endif
#ifdef SIGPIPE
  sigaddset(&action.sa_mask, SIGPIPE);
#endif
#ifdef SIGALRM
  sigaddset(&action.sa_mask, SIGALRM);
#endif
#ifdef SIGTERM
  sigaddset(&action.sa_mask, SIGTERM);
#endif
#ifdef SIGUSR1
  sigaddset(&action.sa_mask, SIGUSR1);
#endif
#ifdef SIGUSR2
  sigaddset(&action.sa_mask, SIGUSR2);
#endif
#ifdef SIGCHLD
  sigaddset(&action.sa_mask, SIGCHLD);
#endif
#ifdef SIGCLD
  sigaddset(&action.sa_mask, SIGCLD);
#endif
#ifdef SIGURG
  sigaddset(&action.sa_mask, SIGURG);
#endif
#ifdef SIGIO
  sigaddset(&action.sa_mask, SIGIO);
#endif
#ifdef SIGPOLL
  sigaddset(&action.sa_mask, SIGPOLL);
#endif
#ifdef SIGXCPU
  sigaddset(&action.sa_mask, SIGXCPU);
#endif
#ifdef SIGXFSZ
  sigaddset(&action.sa_mask, SIGXFSZ);
#endif
#ifdef SIGVTALRM
  sigaddset(&action.sa_mask, SIGVTALRM);
#endif
#ifdef SIGPROF
  sigaddset(&action.sa_mask, SIGPROF);
#endif
#ifdef SIGPWR
  sigaddset(&action.sa_mask, SIGPWR);
#endif
#ifdef SIGLOST
  sigaddset(&action.sa_mask, SIGLOST);
#endif
#ifdef SIGWINCH
  sigaddset(&action.sa_mask, SIGWINCH);
#endif

  for (i = 0; k_exception_signals[i] != -1; ++ i)
    sigaddset(&action.sa_mask, k_exception_signals[i]);

  action.sa_flags = SA_ONSTACK | SA_SIGINFO;

  action.sa_sigaction = fault_handler_sigaction;

  for (i = 0; k_exception_signals[i] != -1; ++ i)
    sigaction(k_exception_signals[i], &action, (struct sigaction *) NULL);

  sigaction(SIGQUIT, &action, (struct sigaction *) NULL);

  return 0;
}

#define BACKTRACE_SIZE              128
#define SEGMENT_FAULT_STRING_LEN    4096
static void fault_handler_sigaction(int signum, siginfo_t *si, void *misc)
{
  void *stacks[BACKTRACE_SIZE];
  char buffer[512];
  char cmdline[256];

  char stack_buffer[SEGMENT_FAULT_STRING_LEN];
  int len = 0;

  char **symbols;
  int i, nptrs;
  FILE *fp;
  int pid;
  const char *sbuffer = NULL;

  pid = (int) getpid();
  snprintf(buffer, sizeof(buffer), "/proc/%d/cmdline", pid);
  memset(cmdline, 0, sizeof(cmdline));
  if ((fp = fopen(buffer, "r")) == NULL) {
    snprintf(cmdline, sizeof(cmdline), "debugme");
  } else {
    fread(cmdline, sizeof(cmdline), 1, fp);
    fclose(fp);
  }

  len += snprintf(stack_buffer+len, SEGMENT_FAULT_STRING_LEN-len,
                  "\n************************************************************************************\n\n");
  len += snprintf(stack_buffer+len, SEGMENT_FAULT_STRING_LEN-len,
                  "!PID: %d, cmdline: %s\n!Caught signal %s(%d), may crash address is %p\n"
                  "!errno: %d, code: %d\n", pid, cmdline, _signal[si->si_signo],
                  si->si_signo, si->si_addr, si->si_errno, si->si_code);

  nptrs = backtrace(stacks, BACKTRACE_SIZE);
  symbols = backtrace_symbols(stacks, nptrs);
  if (!symbols) {
    len += snprintf(stack_buffer+len, SEGMENT_FAULT_STRING_LEN-len,
                    "!Backtrace stopped: previous frame inner to this frame (corrupt stack?)");
    len += snprintf(stack_buffer+len, SEGMENT_FAULT_STRING_LEN-len,
                    "\n************************************************************************************\n\n");
  } else {
    // Print func callback
    for (i = 0; i < nptrs; ++i) {
      if (si->si_signo == SIGSEGV)
        sbuffer = demangle_using_addr2line(pid, buffer, symbols[i]);
      else {
        buffer[0] = '\0';
        sbuffer = buffer;
      }

      if (sbuffer[0] == '\0' || strstr(sbuffer, "??") != NULL)
        len += snprintf(stack_buffer+len, SEGMENT_FAULT_STRING_LEN-len, "%s\n",
                        demangle(symbols[i], buffer));
      else
        len += snprintf(stack_buffer+len, SEGMENT_FAULT_STRING_LEN-len, "%s",
                        sbuffer);

      len = len < SEGMENT_FAULT_STRING_LEN ? len : SEGMENT_FAULT_STRING_LEN;
    }

    len += snprintf (stack_buffer+len, SEGMENT_FAULT_STRING_LEN-len,
                     "\n************************************************************************************\n");
    free(symbols);
  }

  LOGW("%s", stack_buffer);

#if defined(DEBUG_GDB) && (DEBUG_GDB != 0)
  char *timestr = buffer;
  gettimestr(timestr);
  snprintf(stack_buffer, SEGMENT_FAULT_STRING_LEN,
           "\nPlease run 'gdb %s %ld' to continue debugging or 'kill -9 %d' (crash time: %s)\n",
           cmdline, (long int) syscall(SYS_gettid), pid, timestr);
  for ( ; ; ) {
    LOGW("%s", stack_buffer);
    sleep_(30 * 1000);
  }
#endif

  sig_crashes_restore();
  raise(signum);
}

static int addr2line(int pid, const char *library, const char *addr, char *buffer)
{
  FILE *fp = NULL;
  char procfile[128], *line = buffer;
  char *rline = NULL, *lib = NULL;

  unsigned long baseaddr, runaddr, vaddr;
  char *cmdline = procfile;

  snprintf(procfile, 128, "/proc/%d/maps", pid);
  if ((fp = fopen(procfile, "r")) == NULL) 
    return -1;
  while ((rline = fgets(line, 512, fp)) != NULL) {
    if (strchr(line, '\n')) *(strchr(line, '\n')) = '\0';

    if (strstr(line, "r-xp") == NULL) continue;
    if (strstr(line, library) != NULL) break;
  }
  fclose(fp);

  if (rline == NULL)
    return -1;

  if (strrchr(line, ' ')) lib = strrchr(line, ' ') + 1;

  if (strchr(line, '-')) *(strchr(line, '-')) = '\0';
  baseaddr = (unsigned long) strtoll(line, NULL, 16);
  runaddr  = (unsigned long) strtoll(addr, NULL, 16);

  if (strstr (lib, ".so") == NULL)
    vaddr = runaddr;
  else
    vaddr = runaddr - baseaddr;

  snprintf(cmdline, 128, "addr2line -C -f -e %s %x", lib, (unsigned int) vaddr);

  if ((fp = popen (cmdline, "r")) == NULL) 
    return 3;

  memset (buffer, 0, 512);
  if (fread (buffer, 512, 1, fp) < 0) {
    fclose (fp);
    return 4;
  }
  fclose (fp);

  if (strchr(buffer, '\n')) *(strchr(buffer, '\n')) = '\t';

  return 0;
}

static const char *demangle_using_addr2line(int pid, char *buffer, const char *symbol)
{
  char library [256], addr[128];
  char *lib = library;

  if (2 != sscanf(symbol, "%255[^(]%*[^[][%63[^]]", library, addr) && 
      2 != sscanf(symbol, "%255[^ ] [%63[^]]", library, addr)) {
    buffer [0] = '\0';
    return buffer;
  }

  if (strrchr(library, '/')) lib = strrchr(library, '/') + 1;

  if (addr2line(pid, lib, addr, buffer) != 0) {
    buffer [0] = '\0';
    return buffer;
  }

  return buffer;
}

static const char *demangle(const char *symbol, char *buffer)
{
  size_t size;
  int status;
  char *sbuffer = buffer, *demangled;

  if (1 == sscanf(symbol, "%*[^(]%*[^_]%384[^)+]", sbuffer)) {
    if (NULL != (demangled = abi::__cxa_demangle(sbuffer, NULL, &size, &status))) {
      snprintf(buffer, 512, "%s", demangled);
      free(demangled);
      return buffer;
    }
  }

  if (1 == sscanf(symbol, "%384s", sbuffer))
    return buffer;

  return symbol;
}

static void sig_crashes_restore()
{
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = SIG_DFL;
  for (unsigned i = 0; k_exception_signals[i] != -1; ++ i)
    sigaction(k_exception_signals[i], &action, NULL);
  sigaction(SIGQUIT, &action, NULL);

  if (_need_free_sigstack) {
    stack_t stack;
    if (sigaltstack(NULL, &stack) != -1 && stack.ss_sp)
      SAFE_FREE(stack.ss_sp);
    _need_free_sigstack = false;
  }
}

static int gettimestr(char *buf)
{
  struct timeval tv;
  if (-1 == gettimeofday(&tv, NULL)) {
    fprintf(stderr, "gettimeofday failed: %s\n", ERRNOMSG);
    goto bail;
  } else {
    time_t time = tv.tv_sec;
    struct tm *ptm = localtime(&time);
    if (!ptm) {
      fprintf(stderr, "localtime failed: %s\n", ERRNOMSG);
      goto bail;
    }
    sprintf(buf, "%04d-%02d-%02d-%02d:%02d:%02d.%03ld ",
            ptm->tm_year+1900, ptm->tm_mon+1, ptm->tm_mday,
            ptm->tm_hour, ptm->tm_min, ptm->tm_sec,
            tv.tv_usec/1000);
    return 0;
  }
bail:
  strcpy(buf, "UnKnown");
  return -1;
}

}
