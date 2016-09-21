#ifndef _RTSP_CLIENT_H_
#define _RTSP_CLIENT_H_

#include <xnet.h>
#include <xqueue.h>

#include "rtsp_common.h"

using namespace xnet;

namespace flvpusher {

enum ServerState {
  StateInit = 0,
  StateConnected,
  StateReady,
  StatePlaying,
  StatePause,
};

enum TransportMode {
  RtpUdp = 1,
  RtpTcp,
  RawUdp
};

struct RtspUrl {
  AddressPort srvap;
  std::string username;
  std::string passwd;
  std::string stream_name;

  std::string to_string() const;
};

struct RtspRecvBuf {
  uint8_t buf[RTSP_MSG_BUFSIZ];
  int nread;
  uint8_t *last_crlf;

  RtspRecvBuf();
  int get_max_bufsz() const;
  void reset();
};

class Rtsp : public Tcp {
public:
  Rtsp();
  virtual ~Rtsp();

  void add_field(const std::string &field);
  std::string field2string() const;

protected:
  static int parse_url(const std::string surl, RtspUrl &rtsp_url);

protected:
  ServerState m_stat;
  int m_cseq;
  std::string m_session;
  std::vector<std::string> m_fields;
};

/////////////////////////////////////////////////////////////

class MediaSession;
class MediaSubsession;

class RtspClient : public Rtsp {
private:
  struct ResponseInfo {
    unsigned response_code;
    char *response_str;
    char *session_parm_str;
    char *transport_parm_str;
    char *scale_parm_str;
    char *range_parm_str;
    char *rtp_info_parm_str;
    char *public_parm_str;
    char *content_base_parm_str;
    char *content_type_parm_str;
    char *body_start;
    unsigned num_body_bytes;

    ResponseInfo();
    ~ResponseInfo();
    void reset();
  };

public:
  RtspClient(void *opaque = NULL);
  virtual ~RtspClient();

  int open(const std::string &url, AddressPort &ap);
  void close();

  int send_request(const char *cmd_url, const std::string &request, const std::string &content = "");
  int recv_response(ResponseInfo *ri, uint8_t request_byte = 0xFF);
  int request_options(TaskFunc *proc = NULL);
  int request_describe(std::string &sdp, TaskFunc *proc = NULL);
  int request_setup(const std::string &sdp, bool stream_outgoing = false, bool stream_using_tcp = false);
  int request_play();
  int request_teardown();
  int request_get_parameter(TaskFunc *proc = NULL);
  int request_announce(const std::string &sdp);

  int request_setup(MediaSubsession *subsession,
                    bool stream_outgoing = false,
                    bool stream_using_tcp = false,
                    bool force_multicast_on_unspecified = false);
  int request_play(MediaSession *session,
                   double start = 0.0f, double end = -1.0f, float scale = 1.0f);

  void construct_subsession_url(MediaSubsession const *subsession,
                                const char *&prefix,
                                const char *&separator,
                                const char *&suffix);
  const char *session_url(MediaSession const *session) const;

  void set_user_agent_str(const std::string &user_agent_str)
  { m_user_agent_str = user_agent_str; }

  double &duration() { return m_duration; }

  int loop(volatile bool *watch_variable);

  TaskScheduler *scheduler() const { return m_scheduler; }

  static void continue_after_options(void *client_data);
  static void continue_after_describe(void *client_data);
  static void continue_after_get_parameter(void *client_data);

  static void handle_alternative_request_byte(void *, uint8_t request_byte);
  void handle_alternative_request_byte1(uint8_t request_byte);

  static void stream_timer_handler(void *client_data);
  static void shutdown_stream(RtspClient *rtsp_client);

private:
  static char *get_line(char *start_of_line);
  static bool parse_response_code(char *line,
                                  unsigned &response_code, char *&response_string);
  static bool check_for_header(char *line,
                               char const *header_name, unsigned header_name_length,
                               char *&header_parm);

  int parse_transport_parms(const char *parms_str,
                            char *&server_address_str, PortNumBits &server_port_num);

  char *create_blocksize_string(bool stream_using_tcp);

  std::string generate_cmd_url(const char *base_url,
                               MediaSession *session = NULL, MediaSubsession *subsession = NULL);

  void schedule_liveness_command();
  static void send_liveness_command(void *client_data);

  static bool rtsp_option_is_supported(const char *command_name,
                                       const char *public_parm_str);

private:
  RtspRecvBuf m_rrb;
  std::string m_user_agent_str;
  char *m_base_url;
  uint16_t m_desired_max_incoming_packet_size;
  unsigned m_session_timeout_parameter;
  double m_duration;
  char *m_last_session_id;
  TaskToken m_liveness_command_task;
  TaskToken m_stream_timer_task;
  MediaSession *m_sess;
  bool m_server_supports_get_parameter;
  void *m_opaque;
  int m_tcp_stream_id_count;
  TaskScheduler *m_scheduler;
  TaskFunc *m_continue_after_options,
           *m_continue_after_get_parameter;
  xutil::Queue<std::string> m_requests;
};

}

#endif /* end of _RTSP_CLIENT_H_ */
