#ifndef _RTP_INTERFACE_H_
#define _RTP_INTERFACE_H_

#include <xnet.h>

using namespace xnet;

namespace flvpusher {

class TaskScheduler;

typedef void server_request_alternative_byte_handler(void* instance, uint8_t request_byte);

class SocketDescriptor {
public:
  SocketDescriptor(TaskScheduler *scheduler, int socket_num);
  virtual ~SocketDescriptor();

  void register_interface(unsigned char stream_channel_id, void *);
  void *lookup_interface(unsigned char stream_channel_id);
  void deregister_interface(unsigned char stream_channel_id);

  void set_server_request_alternative_byte_handler(server_request_alternative_byte_handler *handler,
                                                   void *client_data) {
    m_server_request_alternative_byte_handler = handler;
    m_server_request_alternative_byte_handler_client_data = client_data;
  }

private:
  static void tcp_read_handler(SocketDescriptor *, int mask);
  bool tcp_read_handler1(int mask);

private:
  TaskScheduler *m_scheduler;
  int m_our_socket_num;
  std::map<unsigned char, void *> m_sub_channel_map;
  server_request_alternative_byte_handler *m_server_request_alternative_byte_handler;
  void *m_server_request_alternative_byte_handler_client_data;
  unsigned char m_stream_channel_id, m_size_byte1;
  bool m_read_error_occurred, m_delete_myself_next, m_are_in_read_handler_loop;
  enum {
    AWAITING_DOLLAR,
    AWAITING_STREAM_CHANNEL_ID,
    AWAITING_SIZE1,
    AWAITING_SIZE2,
    AWAITING_PACKET_DATA
  } m_tcp_reading_state;
};

struct TcpStreamRecord;

class RtpInterface : public Udp {
  friend class SocketDescriptor;
public:
  RtpInterface(TaskScheduler *scheduler = NULL);
  RtpInterface(TaskScheduler *scheduler, const AddressPort &remote);
  RtpInterface(TaskScheduler *scheduler, const char *ip, const uint16_t port);
  virtual ~RtpInterface();

  void set_stream_socket(int sockfd, unsigned char stream_channel_id);
  void remove_stream_socket(int sock_num, unsigned char stream_channel_id);

  virtual int write(const uint8_t *buf, int size,
                    struct sockaddr_in *remote = NULL);

  static void set_server_request_alternative_byte_handler(int socket_num,
                                                          server_request_alternative_byte_handler *handler,
                                                          void *client_data);

private:
  int send_rtp_or_rtcp_packet_over_tcp(uint8_t *packet, unsigned packet_size,
                                       int socket_num, unsigned char stream_channel_id);
  int send_data_over_tcp(int socket_num,
                         uint8_t *data, unsigned data_size);

private:
  TaskScheduler *m_scheduler;
  std::vector<TcpStreamRecord *> m_tcp_stream_record;
  unsigned short m_next_tcp_read_size;
  int m_next_tcp_read_stream_socket_num;
  unsigned char m_next_tcp_read_stream_channel_id;
};

}

#endif /* end of _RTP_INTERFACE_H_ */
