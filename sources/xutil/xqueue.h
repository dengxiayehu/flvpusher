#ifndef _XQUEUE_H_
#define _XQUEUE_H_

#include <queue>

#include "xutil.h"
#include "xlog.h"

namespace xutil {

template <typename T>
class Queue {
public:
  Queue();
  ~Queue();

  int push(const T &item);
  int pop(T &item);
  int front(T &item) const;
  int back(T &item) const;

  int size() const;
  void cancel_wait();

private:
  std::queue<T> m_queue;
  volatile bool m_cancel_wait;

  mutable xutil::RecursiveMutex m_mutex;
  mutable xutil::Condition m_cond;
};

template <typename T>
Queue<T>::Queue() :
  m_cancel_wait(false),
  m_cond(m_mutex)
{
}

template <typename T>
Queue<T>::~Queue()
{
}

template <typename T>
int Queue<T>::push(const T &item)
{
  xutil::AutoLock _l(m_mutex);

  m_queue.push(item);

  if (m_queue.size() == 1) {
    if (m_cond.signal() < 0)
      return -1;
  }

  return 0;
}

template <typename T>
int Queue<T>::front(T &item) const
{
  xutil::AutoLock _l(m_mutex);

  while (m_queue.empty() && !m_cancel_wait) {
    if (m_cond.wait() < 0)
      return -1;
  }

  if (m_queue.empty())
    return -1;

  item = m_queue.front();
  return 0;
}

template <typename T>
int Queue<T>::back(T &item) const
{
  xutil::AutoLock _l(m_mutex);

  while (m_queue.empty() && !m_cancel_wait) {
    if (m_cond.wait() < 0)
      return -1;
  }

  if (m_queue.empty())
    return -1;

  item = m_queue.back();
  return 0;
}

template <typename T>
int Queue<T>::pop(T &item)
{
  if (front(item) < 0)
    return -1;

  xutil::AutoLock _l(m_mutex);
  m_queue.pop();
  return 0;
}

template <typename T>
int Queue<T>::size() const
{
  xutil::AutoLock _l(m_mutex);

  return m_queue.size();
}

template <typename T>
void Queue<T>::cancel_wait()
{
  xutil::AutoLock _l(m_mutex);

  m_cancel_wait = true;
  m_cond.broadcast();
}

}

#endif /* end of _XQUEUE_H_ */
