#include <memory>
#include <xlog.h>
#include <get_bits.h>
#include <xmedia.h>
#include <amf.h>

#include "rtsp_common.h"
#include "common/media_pusher.h"

using namespace std;
using namespace xmedia;
using namespace xutil;
using namespace amf;

namespace flvpusher {

std::map<int, SocketDescriptor *> g_socket_table;

intptr_t DelayQueueEntry::token_counter = 0;

DelayQueueEntry::DelayQueueEntry(timeval tv) :
  m_delta_time_remaining(tv)
{
  m_next = m_prev = this;
  m_token = ++token_counter;
}

DelayQueueEntry::~DelayQueueEntry()
{
}

void DelayQueueEntry::handle_timeout()
{
  delete this;
}

AlarmHandler::AlarmHandler(TaskFunc *proc, void *client_data, timeval tv) :
  DelayQueueEntry(tv), m_proc(proc), m_client_data(client_data)
{
}

#define DELAY_ZERO (timeval) {0, 0}

DelayQueue::DelayQueue() :
  DelayQueueEntry((timeval){INT_MAX, MILLION-1}),
  m_last_sync_time(DELAY_ZERO)
{
}

DelayQueue::~DelayQueue()
{
}

void DelayQueue::add_entry(DelayQueueEntry *new_entry)
{
  synchronize();

  DelayQueueEntry *cur = head();
  while (new_entry->m_delta_time_remaining >= cur->m_delta_time_remaining) {
    new_entry->m_delta_time_remaining -=
      cur->m_delta_time_remaining;
    cur = cur->m_next;
  }

  cur->m_delta_time_remaining -=
    new_entry->m_delta_time_remaining;

  new_entry->m_next = cur;
  new_entry->m_prev = cur->m_prev;
  cur->m_prev = new_entry->m_prev->m_next = new_entry;
}

void DelayQueue::synchronize()
{
  timeval now = time_now();
  if (now < m_last_sync_time) {
    m_last_sync_time = now;
    return;
  }
  timeval time_since_last_sync = now - m_last_sync_time;
  m_last_sync_time = now;

  DelayQueueEntry *cur_entry = head();
  while (time_since_last_sync >= cur_entry->m_delta_time_remaining) {
    time_since_last_sync -= cur_entry->m_delta_time_remaining;
    cur_entry->m_delta_time_remaining = DELAY_ZERO;
    cur_entry = cur_entry->m_next;
  }
  cur_entry->m_delta_time_remaining -= time_since_last_sync;
}

void DelayQueue::remove_entry(DelayQueueEntry *entry)
{
  if (entry == NULL || entry->m_next == NULL) return;

  entry->m_next->m_delta_time_remaining += entry->m_delta_time_remaining;
  entry->m_prev->m_next = entry->m_next;
  entry->m_next->m_prev = entry->m_prev;
  entry->m_next = entry->m_prev = NULL;
}

DelayQueueEntry *DelayQueue::remove_entry(intptr_t token_to_find)
{
  DelayQueueEntry* entry = find_entry_by_token(token_to_find);
  remove_entry(entry);
  return entry;
}

DelayQueueEntry *DelayQueue::find_entry_by_token(intptr_t token_to_find)
{
  DelayQueueEntry *cur = head();
  while (cur != this) {
    if (cur->token() == token_to_find) return cur;
    cur = cur->m_next;
  }
  return NULL;
}

const timeval DelayQueue::time_to_next_alarm()
{
  if (head()->m_delta_time_remaining == DELAY_ZERO)
    return DELAY_ZERO;

  synchronize();
  return head()->m_delta_time_remaining;
}

void DelayQueue::handle_alarm()
{
  if (head()->m_delta_time_remaining != DELAY_ZERO)
    synchronize();

  if (head()->m_delta_time_remaining == DELAY_ZERO) {
    DelayQueueEntry *to_remove = head();
    remove_entry(to_remove);
    to_remove->handle_timeout();
  }
}

TaskScheduler::TaskScheduler(unsigned max_scheduler_granularity) :
  m_max_scheduler_granularity(max_scheduler_granularity),
  m_max_num_sockets(0),
  m_last_handled_socket_num(-1),
  m_watch_variable(NULL)
{
  FD_ZERO(&m_read_set);
  FD_ZERO(&m_write_set);
  FD_ZERO(&m_exception_set);

  m_handlers = new HandlerSet;
}

TaskScheduler::~TaskScheduler()
{
  SAFE_DELETE(m_handlers);
}

int TaskScheduler::do_event_loop(volatile bool *watch_variable)
{
  m_watch_variable = watch_variable;
  for ( ; ; ) {
    if (quit()) break;
    if (single_step() < 0)
      return -1;
  }
  return 0;
}

int TaskScheduler::single_step(unsigned max_delay_time)
{
  fd_set read_set = m_read_set;
  fd_set write_set = m_write_set;
  fd_set exception_set = m_exception_set;

  struct timeval tv = m_delay_queue.time_to_next_alarm();
  const long MAX_TV_SEC = MILLION;
  if (tv.tv_sec > MAX_TV_SEC)
    tv.tv_sec = MAX_TV_SEC;
  if (max_delay_time > 0 &&
      (tv.tv_sec > (long) max_delay_time/MILLION ||
       (tv.tv_sec == (long) max_delay_time/MILLION &&
        tv.tv_usec > (long) max_delay_time%MILLION))) {
    tv.tv_sec = max_delay_time/MILLION;
    tv.tv_usec = max_delay_time%MILLION;
  }

  int res = select(m_max_num_sockets, &read_set, &write_set, &exception_set, &tv);
  if (res < 0) {
    if (errno != EINTR && errno != EAGAIN) {
      LOGE("single_step(): select() failes: %s", ERRNOMSG);
      return -1;
    }
    return 0;
  }

  HandlerSet::Iterator it = m_handlers->begin();
  if (m_last_handled_socket_num >= 0) {
    while (it != m_handlers->end()) {
      if ((*it)->socket_num == m_last_handled_socket_num)
        break;
      ++it;
    }
    if (it == m_handlers->end()) {
      m_last_handled_socket_num = -1;
      it = m_handlers->begin();
    } else {
      ++it;
    }
  }
  while (it != m_handlers->end()) {
    int sock = (*it)->socket_num;
    int result_condition_set = 0;
    if (FD_ISSET(sock, &read_set) && FD_ISSET(sock, &m_read_set))
      result_condition_set |= SOCKET_READABLE;
    if (FD_ISSET(sock, &write_set) && FD_ISSET(sock, &m_write_set))
      result_condition_set |= SOCKET_WRITABLE;
    if (FD_ISSET(sock, &exception_set) && FD_ISSET(sock, &m_exception_set))
      result_condition_set |= SOCKET_EXCEPTION;
    if ((result_condition_set&(*it)->condition_set) != 0 &&
        (*it)->handler_proc != NULL) {
      m_last_handled_socket_num = sock;
      ((*it)->handler_proc)((*it)->client_data, result_condition_set);
      break;
    }
    ++it;
  }
  if (it == m_handlers->end() && m_last_handled_socket_num >= 0) {
    it = m_handlers->begin();
    while (it != m_handlers->end()) {
      int sock = (*it)->socket_num;
      int result_condition_set = 0;
      if (FD_ISSET(sock, &read_set) && FD_ISSET(sock, &m_read_set))
        result_condition_set |= SOCKET_READABLE;
      if (FD_ISSET(sock, &write_set) && FD_ISSET(sock, &m_write_set))
        result_condition_set |= SOCKET_WRITABLE;
      if (FD_ISSET(sock, &exception_set) && FD_ISSET(sock, &m_exception_set))
        result_condition_set |= SOCKET_EXCEPTION;
      if ((result_condition_set&(*it)->condition_set) != 0 &&
          (*it)->handler_proc != NULL) {
        m_last_handled_socket_num = sock;
        ((*it)->handler_proc)((*it)->client_data, result_condition_set);
        break;
      }
      ++it;
    }
    if (it == m_handlers->end())
      m_last_handled_socket_num = -1;
  }

  m_delay_queue.handle_alarm();
  return 0;
}

void TaskScheduler::set_background_handling(int socket_num,
                                            int condition_set, BackgroundHandlerProc *handler_proc, void *client_data)
{
  if (socket_num < 0) return;
  FD_CLR((unsigned) socket_num, &m_read_set);
  FD_CLR((unsigned) socket_num, &m_write_set);
  FD_CLR((unsigned) socket_num, &m_exception_set);
  if (!condition_set) {
    m_handlers->clear_handler(socket_num);
    if (socket_num + 1 == m_max_num_sockets)
      --m_max_num_sockets;
  } else {
    m_handlers->assign_handler(socket_num, condition_set, handler_proc, client_data);
    if (socket_num + 1 > m_max_num_sockets)
      m_max_num_sockets = socket_num + 1;
    if (condition_set&SOCKET_READABLE) FD_SET((unsigned)socket_num, &m_read_set);
    if (condition_set&SOCKET_WRITABLE) FD_SET((unsigned)socket_num, &m_write_set);
    if (condition_set&SOCKET_EXCEPTION) FD_SET((unsigned)socket_num, &m_exception_set);
  }
}

TaskToken TaskScheduler::schedule_delayed_task(int64_t microseconds, TaskFunc *proc,
                                               void *client_data)
{
  if (microseconds < 0) microseconds = 0;
  struct timeval tv = {(long)microseconds/MILLION, (long)microseconds%MILLION};
  AlarmHandler *alarm_handler = new AlarmHandler(proc, client_data, tv);
  m_delay_queue.add_entry(alarm_handler);
  return (void *)(alarm_handler->token());
}

void TaskScheduler::unschedule_delayed_task(TaskToken &prev_task)
{
  DelayQueueEntry *alarm_handler = m_delay_queue.remove_entry((intptr_t) prev_task);
  prev_task = NULL;
  delete alarm_handler;
}

HandlerSet::HandlerSet()
{
}

HandlerSet::~HandlerSet()
{
  FOR_VECTOR_ITERATOR(HandlerDescriptor *, m_handlers, it) {
    SAFE_DELETE((*it));
  }
  m_handlers.clear();
}

void HandlerSet::assign_handler(int socket_num, int condition_set,
    TaskScheduler::BackgroundHandlerProc *handler_proc, void *client_data)
{
  HandlerDescriptor *handler = NULL;
  FOR_VECTOR_ITERATOR(HandlerDescriptor *, m_handlers, it) {
    if ((*it)->socket_num == socket_num) {
      handler = (*it);
      break;
    }
  }
  if (!handler) {
    handler = new HandlerDescriptor;
    m_handlers.push_back(handler);
    handler->socket_num = socket_num;
  }
  handler->condition_set = condition_set;
  handler->handler_proc = handler_proc;
  handler->client_data = client_data;
}

void HandlerSet::clear_handler(int socket_num)
{
  FOR_VECTOR_ITERATOR(HandlerDescriptor *, m_handlers, it) {
    if ((*it)->socket_num == socket_num) {
      SAFE_DELETE(*it);
      m_handlers.erase(it);
      break;
    }
  }
}

void HandlerSet::move_handler(int old_socket_num, int new_socket_num)
{
  HandlerDescriptor *handler = NULL;
  FOR_VECTOR_ITERATOR(HandlerDescriptor *, m_handlers, it) {
    if ((*it)->socket_num == old_socket_num) {
      handler = (*it);
      break;
    }
  }
  if (handler) {
    handler->socket_num = new_socket_num;
  }
}

/////////////////////////////////////////////////////////////

uint32_t random32()
{
  int r_1 = rand();
  uint32_t r16_1 = (uint32_t) (r_1&0x00FFFF00);

  int r_2 = rand();
  uint32_t r16_2 = (uint32_t) (r_2&0x00FFFF00);

  return (r16_1<<8) | (r16_2>>8);
}

}
