#include <sys/ioctl.h>
#include <xlog.h>

#include "rtp_interface.h"
#include "rtsp_common.h"

//#define XDEBUG

using namespace std;

namespace flvpusher {

static void remove_socket_descriptor(int sock_num)
{
  if (g_socket_table.find(sock_num) != g_socket_table.end()) {
    g_socket_table.erase(sock_num);
  }
}

static void deregister_socket(int sock_num, unsigned char stream_channel_id)
{
  if (g_socket_table.find(sock_num) != g_socket_table.end()) {
    g_socket_table[sock_num]->deregister_interface(stream_channel_id);
  }
}

SocketDescriptor::SocketDescriptor(TaskScheduler *scheduler, int socket_num) :
  m_scheduler(scheduler), m_our_socket_num(socket_num),
  m_server_request_alternative_byte_handler(NULL), m_server_request_alternative_byte_handler_client_data(NULL),
  m_read_error_occurred(false), m_delete_myself_next(false), m_are_in_read_handler_loop(false),
  m_tcp_reading_state(AWAITING_DOLLAR)
{
}

SocketDescriptor::~SocketDescriptor()
{
  m_scheduler->turn_off_background_read_handling(m_our_socket_num);
  remove_socket_descriptor(m_our_socket_num);

  FOR_MAP(m_sub_channel_map, unsigned char, void *, it) {
    unsigned char stream_channel_id = MAP_KEY(it);
    RtpInterface *rtp_interface = (RtpInterface *) MAP_VAL(it);

    rtp_interface->remove_stream_socket(m_our_socket_num, stream_channel_id);
  }
}

void SocketDescriptor::register_interface(unsigned char stream_channel_id, void *interface)
{
  bool is_first_registration = m_sub_channel_map.empty();
  m_sub_channel_map.insert(pair<unsigned char, void *>(stream_channel_id, interface));

  if (is_first_registration) {
    m_scheduler->turn_on_background_read_handling(m_our_socket_num,
                                                  (TaskScheduler::BackgroundHandlerProc *) &tcp_read_handler,
                                                  this);
  }
}

void SocketDescriptor::tcp_read_handler(SocketDescriptor *socket_descriptor, int mask)
{
  // Call the read handler until it returns false, with a limit to avoid starving other sockets
  int nread = 0;
  if (ioctl(socket_descriptor->m_our_socket_num, FIONREAD, &nread) < 0) {
    LOGE("ioctl FIONREAD failed: %s", ERRNOMSG);
    return;
  }
  unsigned count = MIN(2000, nread);

  socket_descriptor->m_are_in_read_handler_loop = true;
  while (!socket_descriptor->m_delete_myself_next &&
      socket_descriptor->tcp_read_handler1(mask) &&
      --count > 0) {
  }
  socket_descriptor->m_are_in_read_handler_loop = false;
  if (socket_descriptor->m_delete_myself_next) {
    delete socket_descriptor;
  }
}

bool SocketDescriptor::tcp_read_handler1(int mask)
{
  uint8_t c;
  if (m_tcp_reading_state != AWAITING_PACKET_DATA) {
    int result = recv(m_our_socket_num, &c, 1, MSG_NOSIGNAL);
    if (!result) {
      LOGD("socket_num (%d) closed", m_our_socket_num);
      return false;
    } else if (result != 1) {
      LOGE("socket_num (%d) recv failed: %s",
           m_our_socket_num, ERRNOMSG);
      m_read_error_occurred = true;
      m_delete_myself_next = true;
      return false;
    }
  }

  bool call_again = true;
  switch (m_tcp_reading_state) {
    case AWAITING_DOLLAR:
      if (c == '$') {
        m_tcp_reading_state = AWAITING_STREAM_CHANNEL_ID;
      } else {
        // This character is part of a RTSP request or command
        if (m_server_request_alternative_byte_handler &&
            c != 0xFF && c != 0xFE) {
          m_server_request_alternative_byte_handler(m_server_request_alternative_byte_handler_client_data, c);
        }
      }
      break;

    case AWAITING_STREAM_CHANNEL_ID:
      if (lookup_interface(c) != NULL) {
        m_stream_channel_id = c;
        m_tcp_reading_state = AWAITING_SIZE1;
      } else {
        // This wasn't a stream channel id that we expected.  We're (somehow) in a strange state.  Try to recover:
        LOGW("SocketDescriptor(socket %d)::tcp_read_handler1(): Saw nonexistent stream channel id: 0x%02x\n",
             m_our_socket_num, c);
        m_tcp_reading_state = AWAITING_DOLLAR;
      }
      break;

    case AWAITING_SIZE1:
      // The byte that we read is the first (high) byte of the 16-bit RTP or RTCP packet 'size'.
      m_size_byte1 = c;
      m_tcp_reading_state = AWAITING_SIZE2;
      break;

    case AWAITING_SIZE2: {
       // The byte that we read is the second (low) byte of the 16-bit RTP or RTCP packet 'size'.
       unsigned short size = (m_size_byte1<<8)|c;

       // Record the information about the packet data that will be read next:
       RtpInterface *rtp_interface = (RtpInterface *) lookup_interface(m_stream_channel_id); 
       if (rtp_interface) {
         rtp_interface->m_next_tcp_read_size = size;
         rtp_interface->m_next_tcp_read_stream_socket_num = m_our_socket_num;
         rtp_interface->m_next_tcp_read_stream_channel_id = m_stream_channel_id;
       }
       m_tcp_reading_state = AWAITING_PACKET_DATA;
     } break;

    case AWAITING_PACKET_DATA: {
       call_again = false;
       m_tcp_reading_state = AWAITING_DOLLAR;
       RtpInterface *rtp_interface = (RtpInterface *) lookup_interface(m_stream_channel_id); 
       if (rtp_interface) {
         if (rtp_interface->m_next_tcp_read_size == 0) {
           // We've already read all the data for this packet
           break;
         }
         LOGW("No handler proc for \"rtp_interface\" for channel %d; need to skip %d remaining bytes\n",
              m_our_socket_num, m_stream_channel_id, rtp_interface->m_next_tcp_read_size);
         int result = recv(m_our_socket_num, &c, 1, MSG_NOSIGNAL);
         if (result < 0) { // error reading TCP socket, so we will no longer handle it
           m_read_error_occurred = true;
           m_delete_myself_next = true;
           return false;
         } else {
           m_tcp_reading_state = AWAITING_PACKET_DATA;
           if (result == 1) {
             --rtp_interface->m_next_tcp_read_size;
             call_again = true;
           }
         }
       } else {
         LOGW("No \"rtp_interface\" for channel %d\n",
              m_our_socket_num, m_stream_channel_id);
       }
     } break;
  }
  return call_again;
}

void *SocketDescriptor::lookup_interface(unsigned char stream_channel_id)
{
  if (m_sub_channel_map.find(stream_channel_id) != m_sub_channel_map.end())
    return m_sub_channel_map[stream_channel_id];
  return NULL;
}

void SocketDescriptor::deregister_interface(unsigned char stream_channel_id)
{
  if (m_sub_channel_map.find(stream_channel_id) != m_sub_channel_map.end()) {
    m_sub_channel_map.erase(stream_channel_id);
  }

  if (m_sub_channel_map.empty() ||
      stream_channel_id == 0xFF) {
    if (m_are_in_read_handler_loop) {
      m_delete_myself_next = true; // we can't delete ourself yet, but we'll do so from "tcp_read_handler()"
    } else {
      delete this;
    }
  }
}

/////////////////////////////////////////////////////////////

struct TcpStreamRecord {
public:
  TcpStreamRecord(int stream_socket_num, unsigned char stream_channel_id);
  virtual ~TcpStreamRecord();

public:
  int m_stream_socket_num;
  unsigned char m_stream_channel_id;
};

TcpStreamRecord::TcpStreamRecord(int stream_socket_num, unsigned char stream_channel_id) :
  m_stream_socket_num(stream_socket_num), m_stream_channel_id(stream_channel_id)
{
}

TcpStreamRecord::~TcpStreamRecord()
{
}

/////////////////////////////////////////////////////////////

RtpInterface::RtpInterface(TaskScheduler *scheduler) :
  m_scheduler(scheduler),
  m_next_tcp_read_size(0),
  m_next_tcp_read_stream_socket_num(-1),
  m_next_tcp_read_stream_channel_id(0xFF)
{
}

RtpInterface::RtpInterface(TaskScheduler *scheduler, const AddressPort &remote) :
  Udp(remote), m_scheduler(scheduler)
{
}

RtpInterface::RtpInterface(TaskScheduler *scheduler, const char *ip, const uint16_t port) :
  Udp(ip, port), m_scheduler(scheduler)
{
}

RtpInterface::~RtpInterface()
{
  FOR_VECTOR_ITERATOR(TcpStreamRecord *, m_tcp_stream_record, it) {
    deregister_socket((*it)->m_stream_socket_num, (*it)->m_stream_channel_id);
    SAFE_DELETE(*it);
  }
  m_tcp_stream_record.clear();
}

void RtpInterface::set_stream_socket(int sockfd, unsigned char stream_channel_id)
{
  if (sockfd < 0) return;

  if (get_sockfd() != -1) {
    m_scheduler->turn_off_background_read_handling(get_sockfd());
    set_sockfd(-1);
  }

  FOR_VECTOR_CONST_ITERATOR(TcpStreamRecord *, m_tcp_stream_record, it) {
    if ((*it)->m_stream_socket_num == sockfd &&
        (*it)->m_stream_channel_id == stream_channel_id) {
      LOGW("sockfd(%d) with stream_channel_id(%d) already registered",
           sockfd, stream_channel_id);
      return;
    }
  }

  TcpStreamRecord *record = new TcpStreamRecord(sockfd, stream_channel_id);
  m_tcp_stream_record.push_back(record);

  SocketDescriptor *socket_descriptor = NULL;
  if (g_socket_table.find(sockfd) == g_socket_table.end()) {
    socket_descriptor = new SocketDescriptor(m_scheduler, sockfd);
    g_socket_table.insert(pair<int, SocketDescriptor *>(sockfd, socket_descriptor));
  } else {
    socket_descriptor = g_socket_table[sockfd];
  }
  socket_descriptor->register_interface(stream_channel_id, this);
}

void RtpInterface::remove_stream_socket(int sock_num, unsigned char stream_channel_id)
{
  for (vector<TcpStreamRecord *>::iterator it = m_tcp_stream_record.begin();
       it != m_tcp_stream_record.end();
       ) {
    if ((*it)->m_stream_socket_num == sock_num &&
        (stream_channel_id == 0xFF || (*it)->m_stream_channel_id == stream_channel_id)) {
      SAFE_DELETE(*it);
      m_tcp_stream_record.erase(it++);

      deregister_socket(sock_num, stream_channel_id);

      if (stream_channel_id != 0xFF) return;
    } else {
      it++;
    }
  }
}

int RtpInterface::write(const uint8_t *buf, int size, struct sockaddr_in *remote)
{
  if (get_sockfd() != -1) {
    return Udp::write(buf, size, remote);
  }

  int ret = -1;
  FOR_VECTOR_CONST_ITERATOR(TcpStreamRecord *, m_tcp_stream_record, it) {
    if (send_rtp_or_rtcp_packet_over_tcp((uint8_t *) buf, size,
          (*it)->m_stream_socket_num, (*it)->m_stream_channel_id) < 0) {
      return -1;
    } else ret = 0;
  }
  return ret;
} 

int RtpInterface::send_rtp_or_rtcp_packet_over_tcp(uint8_t *packet, unsigned packet_size,
    int socket_num, unsigned char stream_channel_id)
{
#ifdef XDEBUG
  LOGD("%d bytes over channel %d (socket %d)",
       packet_size, stream_channel_id, socket_num);
#endif

  uint8_t framing_header[4];
  framing_header[0] = '$';
  framing_header[1] = stream_channel_id;
  framing_header[2] = (uint8_t) ((packet_size&0xFF00)>>8);
  framing_header[3] = (uint8_t) (packet_size&0xFF);

  if (!send_data_over_tcp(socket_num, framing_header, 4) &&
      !send_data_over_tcp(socket_num, packet, packet_size))
    return 0;

  return -1;
}

int RtpInterface::send_data_over_tcp(int socket_num,
    uint8_t *data, unsigned data_size)
{
  if (::send(socket_num, data, data_size, MSG_NOSIGNAL) < 0) {
    LOGE("Write data to network failed");
    remove_stream_socket(socket_num, 0xFF);
    return -1;
  }
  return 0;
}

void RtpInterface::set_server_request_alternative_byte_handler(int socket_num,
                                                               server_request_alternative_byte_handler *handler,
                                                               void *client_data)
{
  if (g_socket_table.find(socket_num) != g_socket_table.end()) {
    g_socket_table[socket_num]->set_server_request_alternative_byte_handler(handler, client_data);
  }
}

}
