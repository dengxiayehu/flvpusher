#ifndef _XNET_H_
#define _XNET_H_

#include "xutil.h"

#define MTU 1500

namespace xnet {

class AddressPort {
  friend std::ostream &operator<<(std::ostream &, const AddressPort &);
public:
  AddressPort();
  AddressPort(const std::string &ip, const uint16_t port);
  AddressPort(const std::string &ip_comma_port);
  ~AddressPort();

  bool set_address(const char *ip);
  bool set_port(const uint16_t port);
  bool set_address_port(const char *ip, const uint16_t port);

  const char *get_address() const;
  const uint16_t get_port() const;

  AddressPort &operator=(const AddressPort &rhs);
  bool operator==(const AddressPort &rhs) const;

  std::string to_string() const;

  void reset();

private:
  std::string m_ip;
  uint16_t m_port;
};

class Socket {
public:
  Socket();
  virtual ~Socket();

  int get_sockfd() const;
  void set_sockfd(int sockfd);
  virtual void close();
  virtual int write(const uint8_t *buf, int size,
                    struct sockaddr_in *remote = NULL);
  virtual int read(uint8_t *buf, int buf_size);
  virtual int readn(uint8_t *buf, int buf_size);
  virtual int connect(const AddressPort &ap);
  virtual bool is_connected() const;

  int increate_receive_buffer_to(int requested_size)
  { return increate_buffer_to(SO_RCVBUF, requested_size); }
  int increate_send_buffer_to(int requested_size)
  { return increate_buffer_to(SO_SNDBUF, requested_size); }

private:
#define BUFFER_CACHE_SIZE   (16*1024)
  struct SockBuf {
    int sb_socket;
    int sb_size;
    char *sb_start;
    char sb_buf[BUFFER_CACHE_SIZE];
    int sb_timeout;
  };

private:
  void sock_buf_init(SockBuf *sb);
  int sock_buf_fill(SockBuf *sb);
  int sock_buf_send(SockBuf *sb, const uint8_t *buf, int size,
      struct sockaddr_in *remote = NULL);
  void sock_buf_close(SockBuf *sb);

  int get_buffer_size(int buf_opt_name);
  int increate_buffer_to(int buf_opt_name, int requested_size);

private:
  SockBuf m_sb;

protected:
  struct sockaddr_in m_bindaddr;
  struct sockaddr_in m_connaddr;
};

class Tcp : public Socket {
public:
  enum { BACKLOG = 5 };
  virtual int open(AddressPort &ap);
  int accept(struct sockaddr *addr, socklen_t *addrlen);
  int listen();

private:
  static const int SockRecvTimeout = 30;
};

class Udp : public Socket {
public:
  Udp();
  Udp(const AddressPort &remote);
  Udp(const char *ip, const uint16_t port);
  virtual ~Udp();

  virtual int open(AddressPort &ap);

  virtual int write(const uint8_t *buf, int size,
                    struct sockaddr_in *remote = NULL);

private:
  void init_remote_addr(const AddressPort &ap);

private:
  struct sockaddr_in *m_remote_addr;
};

std::string our_ip();
int get_local_address_from_sockfd(int sockfd, AddressPort &ap);
int network_wait_fd(int fd, int write, int timeout);

typedef uint32_t NetAddressBits;

class NetAddress {
public:
  NetAddress(const uint8_t *data, unsigned length = 4);
  NetAddress(unsigned length = 4);
  NetAddress(const NetAddress &orig);
  NetAddress &operator=(const NetAddress &rhs);
  virtual ~NetAddress();

  unsigned length() const { return m_length; }
  const uint8_t *data() const { return m_data; }

private:
  void assign(const uint8_t *data, unsigned length);
  void clean();

private:
  unsigned m_length;
  uint8_t *m_data;
};

class NetAddressList {
public:
  NetAddressList(const char *hostname);
  NetAddressList(const NetAddressList &orig);
  NetAddressList& operator=(const NetAddressList &rhs);
  virtual ~NetAddressList();

  unsigned num_addresses() const { return m_num_addresses; };

  const NetAddress *first_address() const;

  class Iterator {
  public:
    Iterator(const NetAddressList &address_list);
    const NetAddress *next_address();

  private:
    const NetAddressList &m_address_list;
    unsigned m_next_index;
  };

private:
  void assign(NetAddressBits num_addresses, NetAddress **address_array);
  void clean();

  friend class Iterator;
  unsigned m_num_addresses;
  NetAddress **m_address_array;
};

typedef uint16_t PortNumBits;

bool is_multicast_address(NetAddressBits address);

}

#endif /* end of _XNET_H_ */
