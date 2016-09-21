#include "xnet.h"

#include <iostream>
#include <cstdlib>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <poll.h>

#include "xlog.h"

//#define XDEBUG

using namespace std;
using namespace xutil;

namespace xnet {

AddressPort::AddressPort()
{
  reset();
}

AddressPort::AddressPort(const string &ip, const uint16_t port) :
  m_ip(ip),
  m_port(port)
{
}

AddressPort::AddressPort(const string &str)
{
  string::size_type pos = str.find(':');
  if (pos == str.npos) {
    LOGE("Invalid string \"\" for AddressPort to parse",
         STR(str));
    reset();
    return;
  }

  m_ip = str.substr(0, pos);
  m_port = atoi(STR(str.substr(pos + 1)));
}

AddressPort::~AddressPort()
{
}

void AddressPort::reset()
{
  m_ip = "0.0.0.0";
  m_port = 0;
}

bool AddressPort::set_address(const char *ip)
{
  if (!is_valid_ip(ip)) {
    LOGE("Invalid IP address or not reachable \"%s\"",
         ip);
    return false;
  }

  m_ip = ip;
  return true;
}

bool AddressPort::set_port(const uint16_t port)
{
  m_port = port;
  return true;
}

bool AddressPort::set_address_port(const char *ip, const uint16_t port)
{
  return set_address(ip) && set_port(port);
}

const char *AddressPort::get_address() const
{
  return m_ip.c_str();
}

const uint16_t AddressPort::get_port() const
{
  return m_port;
}

AddressPort &AddressPort::operator=(const AddressPort &rhs)
{
  if (&rhs == this) {
    // Avoid self-assigment
    return *this;
  }

  m_ip = rhs.m_ip;
  m_port = rhs.m_port;
  return *this;
}

bool AddressPort::operator==(const AddressPort &rhs) const
{
  return !strcmp(m_ip.c_str(), rhs.m_ip.c_str()) && m_port == rhs.m_port;
}

ostream &operator<<(ostream &os, const AddressPort &ap)
{
  os << ap.m_ip << ':' << ap.m_port << std::endl;
  return os;
}

std::string AddressPort::to_string() const
{
  return sprintf_("%s:%d", STR(m_ip), m_port);
}

int get_local_address_from_sockfd(int sockfd, AddressPort &ap)
{
  if (sockfd < 0) {
    LOGE("Invalid sockfd %d passed", sockfd);
    return -1;
  }

  struct sockaddr_in addrin;
  socklen_t addrin_len = sizeof(addrin);
  int ret = getsockname(sockfd,
                        (struct sockaddr *) &addrin, &addrin_len);
  if (ret < 0) {
    LOGE("getsockname failed: %s", ERRNOMSG);
    return -1;
  }

  char ip[INET_ADDRSTRLEN] = {0};
  if (!inet_ntop(AF_INET, &addrin.sin_addr,
                 ip, sizeof(ip))) {
    LOGE("inet_ntop failed: %s", ERRNOMSG);
    return -1;
  }

  if (!strcmp(ip, "0.0.0.0"))
    strcpy(ip, STR(our_ip()));

  ap.set_address_port(ip, ntohs(addrin.sin_port));
  return 0;
}

string our_ip()
{
  struct ifconf conf;
  char buff[BUFSIZ];
  string ip;

  int sockfd = socket(PF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    LOGE("socket failed: %s", ERRNOMSG);
    return "";
  }

  conf.ifc_len = BUFSIZ;
  conf.ifc_buf = buff;
  if (-1 == ioctl(sockfd, SIOCGIFCONF, &conf)) {
    LOGE("ioctl for SIOCGIFCONF failed: %s",
         ERRNOMSG);
    goto out;
  }

  {
    struct ifreq *ifr = conf.ifc_req;
    size_t num = conf.ifc_len/sizeof(struct ifreq);
    for ( ; num--; ++ifr) {
      struct sockaddr_in *sin =
        (struct sockaddr_in *) (&ifr->ifr_addr);

      if (-1 == ioctl(sockfd, SIOCGIFFLAGS, ifr)) {
        LOGE("ioctl for SIOCGIFFLAGS failed: %s",
             ERRNOMSG);
        continue;
      }

      if(((ifr->ifr_flags&IFF_LOOPBACK) == 0) &&
          (ifr->ifr_flags&IFF_UP)) {
        ip = inet_ntoa(sin->sin_addr);
        break;
      }
    }
  }

out:
  SAFE_CLOSE(sockfd);
  return ip;
}

Socket::Socket()
{
  sock_buf_init(&m_sb);
}

Socket::~Socket()
{
  close();
}

void Socket::close()
{
  sock_buf_close(&m_sb);
}

int Socket::write(const uint8_t *buf, int size, struct sockaddr_in *remote)
{
  if (!is_connected())
    return -1;

  int original_size = size;
  const uint8_t *ptr = buf;

  while (size) {
    int nwritten = sock_buf_send(&m_sb, ptr, size, remote);
    if (nwritten < 0) {
      if (errno == EINTR)
        continue;
      LOGE("sock_buf_send() failed: %s", ERRNOMSG);
      close();
      return -1;
    } else if (nwritten == 0)
      return 0;

    size -= nwritten;
    ptr += nwritten;
  }
  return original_size - size;
}

int Socket::read(uint8_t *buf, int buf_size)
{
  if (!is_connected())
    return -1;

  int avail = m_sb.sb_size;
  if (avail >= buf_size) {
    memcpy(buf, m_sb.sb_start, avail);
    m_sb.sb_start += avail;
    m_sb.sb_size -= avail;
    return buf_size;
  } else {
    if (sock_buf_fill(&m_sb) < 1) {
      if (!m_sb.sb_timeout)
        close();
      return 0;
    }
    int n2read = MIN(m_sb.sb_size, buf_size);
    memcpy(buf, m_sb.sb_start, n2read);
    m_sb.sb_start += n2read;
    m_sb.sb_size -= n2read;
    return n2read;
  }
}

int Socket::readn(uint8_t *buf, int buf_size)
{
  if (!is_connected())
    return -1;

  int original_size = buf_size;
  int avail;
  uint8_t *ptr;

  m_sb.sb_timeout = 0;

  ptr = buf;
  while (buf_size > 0) {
    int nread = 0, n2read;

    avail = m_sb.sb_size;
    if (avail == 0) {
      if (sock_buf_fill(&m_sb) < 1) {
        if (!m_sb.sb_timeout)
          close();
        return 0;
      }
      avail = m_sb.sb_size;
    }

    n2read = buf_size < avail ? buf_size : avail;
    if (n2read > 0) {
      memcpy(ptr, m_sb.sb_start, n2read);
      m_sb.sb_start += n2read;
      m_sb.sb_size -= n2read;
      nread = n2read;
    }

    if (nread == 0) {
      LOGI("Socket(%d) closed by peer", get_sockfd());
      close();
      break;
    }

    buf_size -= nread;
    ptr += nread;
  }

  return original_size - buf_size;
}

int Socket::get_sockfd() const
{
  return m_sb.sb_socket;
}

void Socket::set_sockfd(int sockfd)
{
  m_sb.sb_socket = sockfd;
}

int Socket::increate_buffer_to(int buf_opt_name, int requested_size)
{
  int cur_size = get_buffer_size(buf_opt_name);

  while (requested_size < cur_size) {
    socklen_t size_size = sizeof(requested_size);
    if (setsockopt(get_sockfd(), SOL_SOCKET, buf_opt_name,
                   (char *)&requested_size, size_size) >= 0) {
      return requested_size;
    }
    requested_size = (requested_size + cur_size)/2;
  }

  return get_buffer_size(buf_opt_name);
}

int Socket::get_buffer_size(int buf_opt_name)
{
  int cur_size;
  socklen_t size_size = sizeof(cur_size);
  if (getsockopt(get_sockfd(), SOL_SOCKET, buf_opt_name,
                 (char *)&cur_size, &size_size) < 0) {
    LOGE("getsockopt() failed: %s", ERRNOMSG);
    return 0;
  }
  return cur_size;
}

void Socket::sock_buf_init(SockBuf *sb)
{
  memset(sb, 0, sizeof(*sb));
  sb->sb_socket = -1;
}

int Socket::sock_buf_fill(SockBuf *sb)
{
  if (!sb->sb_size)
    sb->sb_start = sb->sb_buf;

  int nread;
  for ( ; ; ) {
    nread = sizeof(sb->sb_buf)-1-sb->sb_size-(sb->sb_start-sb->sb_buf);
    nread = ::recv(sb->sb_socket,
                   sb->sb_start + sb->sb_size, nread, MSG_NOSIGNAL);
    if (nread != -1)
      sb->sb_size += nread;
    else {
      if (errno == EINTR)
        continue;

      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        sb->sb_timeout = 1;
        nread = 0;
      }
    }
    break;
  }
  return nread;
}

int Socket::sock_buf_send(SockBuf *sb, const uint8_t *buf, int size,
                          struct sockaddr_in *remote)
{
  if (remote)
    return ::sendto(sb->sb_socket, buf, size, MSG_NOSIGNAL,
        (struct sockaddr *) remote, sizeof(*remote));
  else
    return ::send(sb->sb_socket, buf, size, MSG_NOSIGNAL);
}

void Socket::sock_buf_close(SockBuf *sb)
{
  SAFE_CLOSE(sb->sb_socket);
}

int Socket::connect(const AddressPort &ap)
{
  memset(&m_connaddr, 0, sizeof(m_connaddr));
  m_connaddr.sin_family = AF_INET;
  m_connaddr.sin_addr.s_addr = inet_addr(ap.get_address());
  m_connaddr.sin_port = htons(ap.get_port());

  if (::connect(get_sockfd(), (struct sockaddr *) &m_connaddr,
                sizeof(struct sockaddr)) < 0) {
    LOGE("connect error: %s", ERRNOMSG);
    return -1;
  }
  return 0;
}

bool Socket::is_connected() const
{
  return get_sockfd() != -1;
}

int Tcp::open(AddressPort &ap)
{
  close();

  int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
  if (sockfd < 0) {
    LOGE("Create socket failed: %s", ERRNOMSG);
    return -1;
  }
  set_sockfd(sockfd);

  int opt = 1;
  setsockopt(get_sockfd(), SOL_SOCKET, SO_REUSEADDR,
             (char *)&opt, sizeof(opt));
  struct timeval tv = {SockRecvTimeout, 0};
  setsockopt(get_sockfd(), SOL_SOCKET, SO_RCVTIMEO,
             (char *)&tv, sizeof(tv));

  memset(&m_bindaddr, 0, sizeof(m_bindaddr));
  m_bindaddr.sin_family = AF_INET;
  m_bindaddr.sin_addr.s_addr = inet_addr(ap.get_address());
  m_bindaddr.sin_port = htons(ap.get_port());

  if (::bind(get_sockfd(), (struct sockaddr *) &m_bindaddr,
             sizeof(struct sockaddr)) < 0) {
    LOGE("bind error: %s", ERRNOMSG);
    return -1;
  }

  if (get_local_address_from_sockfd(get_sockfd(), ap) < 0)
    return -1;
#ifdef XDEBUG
  LOGD("Tcp bind on %s, fd=%d", STR(ap.to_string()), get_sockfd());
#endif
  return 0;
}

int Tcp::accept(struct sockaddr *addr, socklen_t *addrlen)
{
  int connfd = ::accept(get_sockfd(), addr, addrlen);
  if (connfd < 0) {
    LOGE("accept error: %s", ERRNOMSG);
    return -1;
  }
  return connfd;
}

int Tcp::listen()
{
  if (::listen(get_sockfd(), BACKLOG) < 0) {
    LOGE("listen error: %s", ERRNOMSG);
    return -1;
  }
  return 0;
}

Udp::Udp()
{
  init_remote_addr(AddressPort());
}

Udp::Udp(const AddressPort &remote)
{
  init_remote_addr(remote);
}

Udp::Udp(const char *ip, const uint16_t port)
{
  init_remote_addr(AddressPort(ip ? ip : "0.0.0.0", port));
}

void Udp::init_remote_addr(const AddressPort &ap)
{
  if (!strcmp(ap.get_address(), "0.0.0.0")) {
    m_remote_addr = (struct sockaddr_in *) calloc(1, sizeof(struct sockaddr_in));
    m_remote_addr->sin_family = AF_INET;
    m_remote_addr->sin_port = htons(ap.get_port());
    m_remote_addr->sin_addr.s_addr = inet_addr(ap.get_address());
  } else {
    m_remote_addr = NULL;
  }
}

int Udp::open(AddressPort &ap)
{
  close();

  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sockfd < 0) {
    LOGE("Create socket failed: %s", ERRNOMSG);
    return -1;
  }
  set_sockfd(sockfd);

  int opt = 1;
  setsockopt(get_sockfd(), SOL_SOCKET, SO_REUSEADDR,
             (char *)&opt, sizeof(opt));
  opt = 255;
  setsockopt(get_sockfd(), IPPROTO_IP, IP_MULTICAST_TTL,
             (char *)&opt, sizeof(opt));

  memset(&m_bindaddr, 0, sizeof(m_bindaddr));
  m_bindaddr.sin_family = AF_INET;
  m_bindaddr.sin_addr.s_addr = inet_addr(ap.get_address());
  m_bindaddr.sin_port = htons(ap.get_port());
  if (IN_MULTICAST(ntohl(m_bindaddr.sin_addr.s_addr)) ||
      m_bindaddr.sin_addr.s_addr == INADDR_BROADCAST)
    m_bindaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (::bind(get_sockfd(), (struct sockaddr *) &m_bindaddr,
             sizeof(struct sockaddr)) < 0) {
    LOGE("bind error: %s", ERRNOMSG);
    return -1;
  }

  if (get_local_address_from_sockfd(get_sockfd(), ap) < 0)
    return -1;
#ifdef XDEBUG
  LOGD("Udp bind on %s, fd=%d", STR(ap.to_string()), get_sockfd());
#endif

  const char *bind_ip = ap.get_address();
  if (IN_MULTICAST(ntohl(inet_addr(bind_ip)))) {
    opt = 1;
    setsockopt(get_sockfd(), IPPROTO_IP, IP_MULTICAST_LOOP,
               (char *)&opt, sizeof(opt));

    ip_mreq multicast_addr;
    multicast_addr.imr_multiaddr.s_addr = inet_addr(bind_ip);
    multicast_addr.imr_interface.s_addr = htonl(INADDR_ANY);
    setsockopt(get_sockfd(), IPPROTO_IP, IP_ADD_MEMBERSHIP,
               (char *)&multicast_addr, sizeof(multicast_addr));
  }

  if (inet_addr(bind_ip) == INADDR_BROADCAST) {
    opt = 1;
    setsockopt(get_sockfd(), SOL_SOCKET, SO_BROADCAST,
               (char *)&opt, sizeof(opt));
  }
  return 0;
}

int Udp::write(const uint8_t *buf, int size, struct sockaddr_in *remote)
{
  return Socket::write(buf, size, remote ? remote : m_remote_addr);
}

Udp::~Udp()
{
  SAFE_FREE(m_remote_addr);
}

int network_wait_fd(int fd, int write, int timeout)
{
  short int ev = write ? POLLOUT : POLLIN;
  struct pollfd p = {fd, ev, 0};
  int ret;
  ret = poll(&p, 1, timeout);
  return ret < 0 ? errno : p.revents & (ev | POLLERR | POLLHUP) ? 0 : EAGAIN;
}

NetAddress::NetAddress(const uint8_t *data, unsigned length)
{
  assign(data, length);
}

NetAddress::NetAddress(unsigned length) {
  m_data = new uint8_t[length];
  for (unsigned i = 0; i < length; ++i) m_data[i] = 0;
  m_length = length;
}

NetAddress::NetAddress(NetAddress const& orig) {
  assign(orig.data(), orig.length());
}

NetAddress& NetAddress::operator=(const NetAddress &rhs) {
  if (&rhs != this) {
    clean();
    assign(rhs.data(), rhs.length());
  }
  return *this;
}

NetAddress::~NetAddress()
{
  clean();
}

void NetAddress::assign(u_int8_t const* data, unsigned length) {
  m_data = new u_int8_t[length];
  for (unsigned i = 0; i < length; ++i) m_data[i] = data[i];
  m_length = length;
}

void NetAddress::clean() {
  delete[] m_data; m_data = NULL;
  m_length = 0;
}

NetAddressList::NetAddressList(const char *hostname) :
  m_num_addresses(0), m_address_array(NULL)
{
  NetAddressBits addr = inet_addr((char *) hostname);
  if (addr != INADDR_NONE) {
    m_num_addresses = 1;
    m_address_array = new NetAddress*[m_num_addresses];
    m_address_array[0] = new NetAddress((uint8_t *)&addr, sizeof(NetAddressBits));
    return;
  }

#if defined(USE_GETHOSTBYNAME) && (USE_GETHOSTBYNAME != 0)
  struct hostent *host = gethostbyname((char *) hostname);
  if (!host || host->h_length != 4 || !host->h_addr_list) return;
  const uint8_t **const addr_ptr = (const uint8_t **) host->h_addr_list;
  const uint8_t **addr_ptr1 = addr_ptr;
  while (*addr_ptr1) {
    ++m_num_addresses;
    ++addr_ptr1;
  }
  m_address_array = new NetAddress*[m_num_addresses];
  for (unsigned i = 0; i < m_num_addresses; ++i)
    m_address_array[i] = new NetAddress(addr_ptr[i], host->h_length);
#else
  struct addrinfo addrinfo_hints;
  memset(&addrinfo_hints, 0, sizeof(addrinfo_hints));
  addrinfo_hints.ai_family = AF_INET;
  struct addrinfo *addrinfo_res_ptr = NULL;
  int res = getaddrinfo(hostname, NULL, &addrinfo_hints, &addrinfo_res_ptr);
  if (res != 0 || !addrinfo_res_ptr) return;
  const struct addrinfo *p = addrinfo_res_ptr;
  while (p) {
    if (p->ai_addrlen < 4) continue;
    ++m_num_addresses;
    p = p->ai_next;
  }
  m_address_array = new NetAddress*[m_num_addresses];
  unsigned i = 0;
  p = addrinfo_res_ptr;
  while (p) {
    if (p->ai_addrlen < 4) continue;
    m_address_array[i++] =
      new NetAddress((const uint8_t *)&(((struct sockaddr_in *)p->ai_addr)->sin_addr.s_addr), 4);
    p = p->ai_next;
  }
  freeaddrinfo(addrinfo_res_ptr);
#endif
}

NetAddressList::NetAddressList(const NetAddressList &orig)
{
  assign(orig.num_addresses(), orig.m_address_array);
}

NetAddressList& NetAddressList::operator=(const NetAddressList &rhs) {
  if (&rhs != this) {
    clean();
    assign(rhs.num_addresses(), rhs.m_address_array);
  }
  return *this;
}

NetAddressList::~NetAddressList()
{
  clean();
}

void NetAddressList::assign(unsigned num_addresses, NetAddress** address_array) {
  m_address_array = new NetAddress*[num_addresses];
  for (unsigned i = 0; i < num_addresses; ++i)
    m_address_array[i] = new NetAddress(*address_array[i]);
  m_num_addresses = num_addresses;
}

void NetAddressList::clean() {
  while (m_num_addresses-- > 0) {
    delete m_address_array[m_num_addresses];
  }
  delete[] m_address_array; m_address_array = NULL;
}

NetAddress const* NetAddressList::first_address() const {
  if (m_num_addresses == 0) return NULL;
  return m_address_array[0];
}

NetAddressList::Iterator::Iterator(const NetAddressList &address_list) :
  m_address_list(address_list), m_next_index(0)
{
}

const NetAddress *NetAddressList::Iterator::next_address()
{
  if (m_next_index >= m_address_list.num_addresses()) return NULL;
  return m_address_list.m_address_array[m_next_index++];
}

bool is_multicast_address(NetAddressBits address)
{
  NetAddressBits address_in_network_order = htonl(address);
  return address_in_network_order >  0xE00000FF &&
    address_in_network_order <= 0xEFFFFFFF;
}

}
