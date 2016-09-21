#ifndef _RTSP_COMMON_H_
#define _RTSP_COMMON_H_

#include <string>
#include <vector>

#define RTSP_PROTOCOL_PORT  554
#define CRLF    "\r\n"
#define RTSP_MSG_BUFSIZ     20000

namespace flvpusher {

typedef void TaskFunc(void *client_data);
typedef void *TaskToken;

#ifndef MILLION
#  define MILLION 1000000
#endif

inline void normalize_timeval(timeval &tv)
{
  if (tv.tv_usec < 0) {
    int nborrow = (-tv.tv_usec)/MILLION + 1;
    tv.tv_usec += nborrow*MILLION;
    tv.tv_sec -= nborrow;
  } else if (tv.tv_usec >= MILLION) {
    int ngiven = tv.tv_usec/MILLION;
    tv.tv_usec %= MILLION;
    tv.tv_sec += ngiven;
  }
}

inline bool operator>=(timeval arg1, timeval arg2)
{
  normalize_timeval(arg1);
  normalize_timeval(arg2);
  if (arg1.tv_sec > arg2.tv_sec)
    return true;
  else if (arg1.tv_sec < arg2.tv_sec)
    return false;
  else 
    return arg1.tv_usec >= arg2.tv_usec;
}

inline bool operator<(timeval arg1, timeval arg2)
{
  return !(arg1 >= arg2);
}

inline bool operator==(timeval arg1, timeval arg2)
{
  normalize_timeval(arg1);
  normalize_timeval(arg2);
  return arg1.tv_sec == arg2.tv_sec && arg1.tv_usec == arg2.tv_usec;
}

inline bool operator!=(timeval arg1, timeval arg2)
{
  return !(arg1 == arg2);
}

inline void operator-=(timeval &arg1, timeval arg2)
{
  arg1.tv_sec -= arg2.tv_sec;
  arg1.tv_usec -= arg2.tv_usec;
  normalize_timeval(arg1);
}

inline void operator+=(timeval &arg1, timeval &arg2)
{
  arg1.tv_sec += arg2.tv_sec;
  arg1.tv_usec += arg2.tv_usec;
  normalize_timeval(arg1);
}

inline timeval operator-(timeval &arg1, timeval &arg2)
{
  timeval tv;
  tv.tv_sec = arg1.tv_sec - arg2.tv_sec;
  tv.tv_usec = arg1.tv_usec - arg2.tv_usec;
  normalize_timeval(tv);
  return tv;
}

inline timeval time_now()
{
  timeval tv;
  gettimeofday(&tv, NULL);
  return tv;
}

class DelayQueue;

class DelayQueueEntry {
public:
  virtual ~DelayQueueEntry();

  intptr_t token() { return m_token; }

protected:
  DelayQueueEntry(timeval tv);

  virtual void handle_timeout();

private:
  friend class DelayQueue;
  DelayQueueEntry *m_next;
  DelayQueueEntry *m_prev;
  timeval m_delta_time_remaining;

  intptr_t m_token;
  static intptr_t token_counter;
};

class AlarmHandler : public DelayQueueEntry {
public:
  AlarmHandler(TaskFunc *proc, void *client_data, timeval tv);

private:
  virtual void handle_timeout() {
    (*m_proc)(m_client_data);
    DelayQueueEntry::handle_timeout();
  }

private:
  TaskFunc *m_proc;
  void *m_client_data;
};

class DelayQueue : public DelayQueueEntry {
public:
  DelayQueue();
  virtual ~DelayQueue();

  void add_entry(DelayQueueEntry *new_entry);
  void remove_entry(DelayQueueEntry *entry);
  DelayQueueEntry *remove_entry(intptr_t token_to_find);
  const timeval time_to_next_alarm();
  void handle_alarm();

private:
  DelayQueueEntry *head() { return m_next; }
  DelayQueueEntry *find_entry_by_token(intptr_t token_to_find);
  void synchronize();

private:
  timeval m_last_sync_time;
};

class HandlerSet;

class TaskScheduler {
public:
  TaskScheduler(unsigned max_scheduler_granularity = 10000/*microseconds*/);
  ~TaskScheduler();

#define SOCKET_READABLE (1<<1)
#define SOCKET_WRITABLE (1<<2)
#define SOCKET_EXCEPTION (1<<3)

  typedef void BackgroundHandlerProc(void *client_data, int mask);

  int do_event_loop(volatile bool *watch_variable);
  void ask2quit() { if (m_watch_variable) *m_watch_variable = true; }
  bool quit() const { return m_watch_variable ? *m_watch_variable : false; }

  int single_step(unsigned max_delay_time = 10000);

  void turn_on_background_read_handling(int socket_num,
                                        BackgroundHandlerProc *handler_proc, void *client_data)
  { set_background_handling(socket_num, SOCKET_READABLE, handler_proc, client_data); }
  void turn_off_background_read_handling(int socket_num)
  { disable_background_handling(socket_num); }

  void set_background_handling(int socket_num,
                               int condition_set, BackgroundHandlerProc *handler_proc, void *client_data);
  void disable_background_handling(int socket_num)
  { set_background_handling(socket_num, 0, NULL, NULL); }

  TaskToken schedule_delayed_task(int64_t microseconds, TaskFunc *proc,
                                  void *client_data);
  void unschedule_delayed_task(TaskToken &prev_task);

private:
  int m_max_scheduler_granularity;
  int m_max_num_sockets;
  fd_set m_read_set;
  fd_set m_write_set;
  fd_set m_exception_set;
  int m_last_handled_socket_num;
  HandlerSet *m_handlers;
  DelayQueue m_delay_queue;
  volatile bool *m_watch_variable;
};

struct HandlerDescriptor {
  int socket_num;
  int condition_set;
  TaskScheduler::BackgroundHandlerProc *handler_proc;
  void *client_data;
};

class HandlerSet {
  public:
    HandlerSet();
    virtual ~HandlerSet();

    void assign_handler(int socket_num, int condition_set,
                        TaskScheduler::BackgroundHandlerProc *handler_proc, void *client_data);
    void clear_handler(int socket_num);
    void move_handler(int old_socket_num, int new_socket_num);

    typedef std::vector<HandlerDescriptor *> HDVec;
    typedef HDVec::iterator Iterator;
    Iterator begin() { return m_handlers.begin(); }
    Iterator end() { return m_handlers.end(); }

  private:
    HDVec m_handlers;
};

static unsigned const rtp_header_size = 12;

class SocketDescriptor;
extern std::map<int, SocketDescriptor *> g_socket_table;

uint32_t random32();

}

#endif /* end of _RTSP_COMMON_H_ */
