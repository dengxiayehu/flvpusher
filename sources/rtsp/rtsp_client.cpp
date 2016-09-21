#include <xlog.h>

#include "rtsp_client.h"
#include "media_session.h"
#include "media_subsession.h"

#define DEFAULT_USER_AGENT  "flvpusher (dengxiayehu@yeah.net)"

//#define XDEBUG
//#define XDEBUG_RTSP_MESSAGE

using namespace std;
using namespace xutil;

namespace flvpusher {

RtspClient::ResponseInfo::ResponseInfo() :
  response_code(404), response_str(NULL),
  session_parm_str(NULL),
  transport_parm_str(NULL),
  scale_parm_str(NULL),
  range_parm_str(NULL),
  rtp_info_parm_str(NULL),
  public_parm_str(NULL),
  content_base_parm_str(NULL),
  content_type_parm_str(NULL),
  body_start(NULL), num_body_bytes(0)
{
}

RtspClient::ResponseInfo::~ResponseInfo()
{
  reset();
}

void RtspClient::ResponseInfo::reset()
{
  response_code = 404;
  SAFE_FREE(response_str);
  SAFE_FREE(session_parm_str);
  SAFE_FREE(transport_parm_str);
  SAFE_FREE(scale_parm_str);
  SAFE_FREE(range_parm_str);
  SAFE_FREE(rtp_info_parm_str);
  SAFE_FREE(public_parm_str);
  SAFE_FREE(content_base_parm_str);
  SAFE_FREE(content_type_parm_str);
  SAFE_FREE(body_start);
  num_body_bytes = 0;
}

RtspClient::RtspClient(void *opaque) :
  m_user_agent_str(DEFAULT_USER_AGENT),
  m_base_url(NULL),
  m_desired_max_incoming_packet_size(0),
  m_session_timeout_parameter(0),
  m_duration(0.0),
  m_last_session_id(NULL),
  m_liveness_command_task(NULL),
  m_stream_timer_task(NULL),
  m_sess(NULL),
  m_server_supports_get_parameter(false),
  m_opaque(opaque),
  m_tcp_stream_id_count(0),
  m_continue_after_options(NULL),
  m_continue_after_get_parameter(NULL)
{
  m_scheduler = new TaskScheduler;
}

RtspClient::~RtspClient()
{
  SAFE_FREE(m_base_url);
  SAFE_FREE(m_last_session_id);
  SAFE_DELETE(m_sess);
  m_scheduler->unschedule_delayed_task(m_liveness_command_task);
  m_scheduler->unschedule_delayed_task(m_stream_timer_task);
  SAFE_DELETE(m_scheduler);
}

void RtspClient::close()
{
  Tcp::close();
  m_stat = StateInit;
}

int RtspClient::open(const std::string &url,
                     AddressPort &ap)
{
  if (m_stat != StateInit)
    return -1;

  RtspUrl _url;
  if (Rtsp::parse_url(url, _url) < 0)
    return -1;

  m_base_url = strdup(STR(_url.to_string()));

#ifdef XDEBUG
  LOGD("rtsp_url is: %s", m_base_url);
#endif

  if (Tcp::open(ap) < 0)
    return -1;

  if (Tcp::connect(_url.srvap) < 0)
    return -1;

  LOGI("Connected to rtsp server: %s successfully",
       STR(_url.srvap.to_string()));

  m_stat = StateConnected;
  return 0;
}

static char *create_session_string(const char *session_id)
{
  char *session_str;
  if (session_id) {
    session_str = (char *) malloc(20 + strlen(session_id));
    sprintf(session_str, "Session: %s", session_id);
  } else
    session_str = strdup("");
  return session_str;
}

int RtspClient::request_options(TaskFunc *proc)
{
  if (m_stat < StateConnected)
    return -1;

  string cmd_url(generate_cmd_url(m_base_url, m_sess));

  if (m_last_session_id) {
    char *session_str = create_session_string(m_last_session_id);
    add_field(session_str);
    SAFE_FREE(session_str);
  }

  if (send_request(STR(cmd_url), "OPTIONS") < 0)
    return -1;

  if (m_stat == StatePlaying &&
      m_tcp_stream_id_count != 0) {
    m_continue_after_options = proc;
    m_requests.push("OPTIONS");
    return 0;
  }

  ResponseInfo ri;
  if (recv_response(&ri) < 0 || ri.response_code != 200)
    return -1;

  m_server_supports_get_parameter = rtsp_option_is_supported(
      "GET_PARAMETER", ri.public_parm_str);

  if (proc) proc(this);
  return 0;
}

int RtspClient::request_describe(std::string &sdp, TaskFunc *proc)
{
  if (m_stat < StateConnected)
    return -1;

  add_field("Accept: application/sdp");
  if (send_request(STR(generate_cmd_url(m_base_url, NULL)), "DESCRIBE") < 0)
    return -1;

  ResponseInfo ri;
  if (recv_response(&ri) < 0 || ri.response_code != 200)
    return -1;

  if (strncasecmp(ri.content_type_parm_str, "application/sdp", 15)) {
    LOGE("Describe's content-type is not application/sdp");
    return -1;
  }
  sdp.assign(ri.body_start, ri.num_body_bytes);

  if (proc) proc(this);
  return 0;
}

int RtspClient::send_request(const char *cmd_url, const std::string &request, const std::string &content)
{
  ++m_cseq;
  string str(sprintf_("%s %s RTSP/1.0"CRLF
             "CSeq: %d"CRLF
             "User-Agent: %s"CRLF
             "%s"
             CRLF
             "%s",
             STR(request), cmd_url,
             m_cseq,
             STR(m_user_agent_str),
             STR(field2string()),
             STR(content)));
#ifdef XDEBUG_RTSP_MESSAGE
  LOGD("Sent rtsp request:[%s]", STR(str));
#endif
  m_fields.clear();
  return Tcp::write((const uint8_t *) STR(str), str.length());
}

void RtspClient::handle_alternative_request_byte(void *rtsp_client, uint8_t request_byte)
{
  ((RtspClient *) rtsp_client)->handle_alternative_request_byte1(request_byte);
}

void RtspClient::handle_alternative_request_byte1(uint8_t request_byte)
{
  ResponseInfo ri;
  int ret = recv_response(&ri, request_byte);
  if (ret < 0) {
    // Handle error
    LOGE("recv_response error");
  } else if (ri.response_code == 200) {
    string str;
    if (m_requests.pop(str) == 0) {
      if (!strcmp(STR(str), "OPTIONS") &&
          m_continue_after_options) {
        m_continue_after_options(this);
      } else if (!strcmp(STR(str), "GET_PARAMETER") &&
          m_continue_after_get_parameter) {
        m_continue_after_get_parameter(this);
      }
    }
  }
}

int RtspClient::recv_response(ResponseInfo *pri, uint8_t request_byte)
{
  for ( ; ; ) {
    if (request_byte == 0xFF) {
      int nread;
      if ((nread = read(m_rrb.buf+m_rrb.nread, m_rrb.get_max_bufsz()-m_rrb.nread)) < 0)
        return -1;
      m_rrb.nread += nread;
    } else {
      m_rrb.buf[m_rrb.nread++] = request_byte;
    }

    bool end_of_headers = false;
    const uint8_t *ptr = m_rrb.buf;
    if (m_rrb.nread > 3) {
      uint8_t const *const ptr_end = &m_rrb.buf[m_rrb.nread-3];
      while (ptr < ptr_end) {
        if (*ptr++ == '\r' && *ptr++ == '\n' && *ptr++ == '\r' && *ptr++ == '\n') {
          end_of_headers = true;
          break;
        }
      }
    }

    if (end_of_headers) {
      m_rrb.buf[m_rrb.nread] = '\0';
      break;
    } else if (request_byte != 0xFF) {
      return 0;
    }
  }

#ifdef XDEBUG_RTSP_MESSAGE
  LOGD("Recvd rtsp response:[%s]", m_rrb.buf);
#endif

  char *header_data_copy;
  int ret = 0;

  do {
    header_data_copy = (char *) malloc(RTSP_MSG_BUFSIZ);
    strncpy(header_data_copy, (char *) m_rrb.buf, m_rrb.nread);
    header_data_copy[m_rrb.nread] = '\0';

    char *line_start;
    char *next_line_start = header_data_copy;
    do {
      line_start = next_line_start;
      next_line_start = get_line(line_start);
    } while (line_start[0] == '\0' && next_line_start != NULL);

    if (!parse_response_code(line_start, pri->response_code, pri->response_str)) {
      LOGE("Parse response code failed");
      ret = -1;
      break;
    }

    bool reach_end_of_headers;
    unsigned cseq;
    unsigned content_length = 0;
    for ( ; ; ) {
      reach_end_of_headers = true;
      line_start = next_line_start;
      if (!line_start) break;

      next_line_start = get_line(line_start);
      if (line_start[0] == '\0') break;
      reach_end_of_headers = false;

      char *header_parm_str = NULL;
      if (check_for_header(line_start, "CSeq:", 5, header_parm_str)) {
        if (sscanf(header_parm_str, "%u", &cseq) != 1 || cseq <= 0) {
          LOGE("Bad \"CSeq\" header: \"%s\"", line_start);
          break;
        }
        SAFE_FREE(header_parm_str);
      } else if (check_for_header(line_start, "Content-Length:", 15, header_parm_str)) {
        if (sscanf(header_parm_str, "%u", &content_length) != 1) {
          LOGE("Bad \"Content-Length:\" header: \"%s\"", line_start);
          break;
        }
        SAFE_FREE(header_parm_str);
      } else if (check_for_header(line_start, "Session:", 8, pri->session_parm_str)) {
      } else if (check_for_header(line_start, "Transport:", 10, pri->transport_parm_str)) {
      } else if (check_for_header(line_start, "Scale:", 6, pri->scale_parm_str)) {
      } else if (check_for_header(line_start, "Range:", 6, pri->range_parm_str)) {
      } else if (check_for_header(line_start, "RTP-Info:", 9, pri->rtp_info_parm_str)) {
      } else if (check_for_header(line_start, "Public:", 7, pri->public_parm_str)) {
      } else if (check_for_header(line_start, "Content-Base:", 13, pri->content_base_parm_str)) {
      } else if (check_for_header(line_start, "Content-Type:", 13, pri->content_type_parm_str)) {
      }
    }
    if (!reach_end_of_headers) {
      ret = -1;
      break;
    }

#ifdef XDEBUG_RTSP_MESSAGE
    LOGD("response_code: %u, response_str:%s, session_parm_str:%s, transport_parm_str:%s, scale_parm_str:%s, range_parm_str:%s, rtp_info_parm_str:%s, public_parm_str:%s, content_base_parm_str:%s, content_type_parm_str:%s",
         pri->response_code, pri->response_str, pri->session_parm_str, pri->transport_parm_str, pri->scale_parm_str, pri->range_parm_str, pri->rtp_info_parm_str, pri->public_parm_str, pri->content_base_parm_str, pri->content_type_parm_str);
#endif

    unsigned body_offset = next_line_start == NULL ?
      m_rrb.nread : next_line_start - header_data_copy;
    if (content_length) {
      pri->num_body_bytes = m_rrb.nread - body_offset;
      pri->body_start = (char *) malloc(content_length);
      memcpy(pri->body_start, &m_rrb.buf[body_offset], pri->num_body_bytes);
      if (content_length > pri->num_body_bytes) {
        unsigned num_extra_bytes_needed = content_length - pri->num_body_bytes;
        unsigned remaining_buffer_size = m_rrb.get_max_bufsz() - m_rrb.nread;
        if (num_extra_bytes_needed > remaining_buffer_size) {
          LOGW("Response buffer size (%d) is too small for \"Content-Length:\" %d",
               RTSP_MSG_BUFSIZ, content_length);
          ret = -1;
          break;
        }

        // Read num_extra_bytes_needed bytes to fill |Content-Length|
        if (request_byte == 0xFF) {
          int n2read = num_extra_bytes_needed;
          if (readn(m_rrb.buf+m_rrb.nread, n2read) != n2read) {
            ret = -1;
            break;
          }
          memcpy(pri->body_start+pri->num_body_bytes, m_rrb.buf+m_rrb.nread, n2read);
          pri->num_body_bytes += n2read;
          m_rrb.reset();
          break;
        } else {
          ret = 0;
          break;
        }
      }
    }

    int num_extra_bytes_after_response =
      m_rrb.nread - (body_offset + content_length);
    if (num_extra_bytes_after_response != 0) {
      memmove(m_rrb.buf, m_rrb.buf+body_offset+content_length,
              num_extra_bytes_after_response);
      m_rrb.nread = num_extra_bytes_after_response;
    } else {
      m_rrb.reset();
    }
  } while (0);

  SAFE_FREE(header_data_copy);
  if (ret < 0 || pri->response_code != 200) {
    pri->reset();
    if (request_byte != 0xFF) {
      ret = -1;
    }
  }
  return ret;
}

char *RtspClient::get_line(char *start_of_line)
{
  for (char* ptr = start_of_line; *ptr != '\0'; ++ptr) {
    if (*ptr == '\r' || *ptr == '\n') {
      if (*ptr == '\r') {
        *ptr++ = '\0';
        if (*ptr == '\n') ++ptr;
      } else {
        *ptr++ = '\0';
      }
      return ptr;
    }
  }

  return NULL;
}

bool RtspClient::parse_response_code(char *line,
                                     unsigned &response_code, char *&response_string)
{
  if (sscanf(line, "RTSP/%*s%u", &response_code) != 1)
    return false; 

  char *p = line;
  while (p[0] != '\0' &&
      p[0] != ' '  &&
      p[0] != '\t')
    ++p;
  while (p[0] != '\0' &&
      (p[0] == ' '  || p[0] == '\t'))
    ++p;
  response_string = strdup(p);
  return true; 
}

bool RtspClient::check_for_header(char *line,
                                  char const *header_name, unsigned header_name_length,
                                  char *&header_parm)
{
  if (strncasecmp(line, header_name, header_name_length))
    return false;

  unsigned parm_index = header_name_length;
  while (line[parm_index] != '\0' &&
      (line[parm_index] == ' ' || line[parm_index] == '\t'))
    ++parm_index;
  if (line[parm_index] == '\0') return false;

  SAFE_FREE(header_parm);
  header_parm = strdup(&line[parm_index]);
  return true;
}

char *RtspClient::create_blocksize_string(bool stream_using_tcp)
{
  char *blocksize_str;
  uint16_t max_packet_size = m_desired_max_incoming_packet_size;

  const uint16_t header_allowance = stream_using_tcp ? 12 : 50;
  if (max_packet_size < header_allowance)
    max_packet_size = 0;
  else
    max_packet_size -= header_allowance;

  if (max_packet_size > 0) {
    blocksize_str = (char *) malloc(25);
    sprintf(blocksize_str, "Blocksize: %u", max_packet_size);
  } else
    blocksize_str = strdup("");
  return blocksize_str;
}

string RtspClient::generate_cmd_url(const char *base_url,
                                    MediaSession *session, MediaSubsession *subsession)
{
  if (subsession) {
    const char *prefix, *separator, *suffix;
    construct_subsession_url(subsession, prefix, separator, suffix);

    return sprintf_("%s%s%s", prefix, separator, suffix);
  } else if (session)
    return session_url(session);
  else
    return base_url;
}

int RtspClient::request_setup(const std::string &sdp, bool stream_outgoing, bool stream_using_tcp)
{
  m_sess = MediaSession::create_new(this, STR(sdp), m_opaque);
  if (!m_sess) {
    LOGE("Create MediaSession failed");
    return -1;
  }
  return m_sess->setup_subsessions(stream_outgoing, stream_using_tcp);
}

int RtspClient::request_play()
{
  if (m_sess->play_subsessions() == 0) {
    if (m_duration > 0) {
      const unsigned delay_slop = 2;
      m_duration += delay_slop;
      unsigned u_secs_to_delay = m_duration*MILLION;
      m_stream_timer_task = m_scheduler->schedule_delayed_task(
          u_secs_to_delay, (TaskFunc *) stream_timer_handler, this);
    }
    LOGI("Started playing session (for up to %.3lf seconds) ...",
         m_duration);
    return 0;
  }
  return (-1);
}

int RtspClient::request_teardown()
{
  if (!m_last_session_id) {
    LOGE("No RTSP session is currently in progress");
    return -1;
  }

  string cmd_url(generate_cmd_url(m_base_url, m_sess));

  char *session_str = create_session_string(m_last_session_id);
  add_field(session_str);
  SAFE_FREE(session_str);

  if (send_request(STR(cmd_url), "TEARDOWN") < 0)
    return -1;

  if (m_stat == StatePlaying &&
      m_tcp_stream_id_count != 0) {
    m_requests.push("TEARDOWN");
    return 0;
  }

  ResponseInfo ri;
  if (!recv_response(&ri) && ri.response_code == 200) {
    m_stat = StateInit;
  }
  return 0;
}

int RtspClient::request_get_parameter(TaskFunc *proc)
{
  if (!m_last_session_id) {
    LOGE("No RTSP session is currently in progress");
    return -1;
  }

  string cmd_url(generate_cmd_url(m_base_url, m_sess));

  char *session_str = create_session_string(m_last_session_id);
  add_field(session_str);
  SAFE_FREE(session_str);

  if (send_request(STR(cmd_url), "GET_PARAMETER") < 0)
    return -1;

  if (m_stat == StatePlaying &&
      m_tcp_stream_id_count != 0) {
    m_continue_after_get_parameter = proc;
    m_requests.push("GET_PARAMETER");
    return 0;
  }

  ResponseInfo ri;
  if (!recv_response(&ri) && ri.response_code == 200) {
    m_stat = StateInit;
    return -1;
  }

  if (proc) proc(this);
  return 0;
}

int RtspClient::request_announce(const std::string &sdp)
{
  if (m_stat < StateConnected)
    return -1;

  add_field("Content-Type: application/sdp");
  add_field(sprintf_("Content-Length: %d", sdp.length()));
  string cmd_url(generate_cmd_url(m_base_url, NULL));

  if (send_request(STR(cmd_url), "ANNOUNCE", sdp) > 0) {
    ResponseInfo ri;
    if (!recv_response(&ri) && ri.response_code == 200) {
      m_stat = StateInit;
    }
  }
  return 0;
}

void RtspClient::continue_after_get_parameter(void *client_data)
{
  ((RtspClient *) client_data)->schedule_liveness_command();
}

int RtspClient::request_setup(MediaSubsession *subsession,
                              bool stream_outgoing, bool stream_using_tcp, bool force_multicast_on_unspecified)
{
  string cmd_url(generate_cmd_url(m_base_url, NULL, subsession));

  const char *transport_fmt;
  if (!strcmp(subsession->protocol_name(), "UDP"))
    transport_fmt = "Transport: RAW/RAW/UDP%s%s%s=%d-%d";
  else
    transport_fmt = "Transport: RTP/AVP%s%s%s=%d-%d";

  const char *transport_type_str;
  const char *mode_str = stream_outgoing ? ";mode=receive" : "";
  const char *port_type_str;
  PortNumBits rtp_number, rtcp_number;
  if (stream_using_tcp) {
    transport_type_str = "/TCP;unicast";
    port_type_str = ";interleaved";
    rtp_number = m_tcp_stream_id_count++;
    rtcp_number = m_tcp_stream_id_count++;
  } else {
    unsigned conn_address = subsession->connection_endpoint_address();
    bool request_multicast_streaming =
      is_multicast_address(conn_address) || (!conn_address && force_multicast_on_unspecified);
    transport_type_str = request_multicast_streaming ? ";multicast" : ";unicast";
    port_type_str = ";client_port";
    rtp_number = subsession->client_port_num();
    if (!rtp_number) {
      LOGE("Client port number unknown");
      return -1;
    }
    rtcp_number = subsession->rtcp_is_muxed() ? rtp_number : rtp_number + 1;
  }

  unsigned transport_size = strlen(transport_fmt) +
    strlen(transport_type_str) + strlen(mode_str) + strlen(port_type_str) + 2*5;
  char *transport_str = (char *) malloc(transport_size);
  sprintf(transport_str, transport_fmt,
          transport_type_str, mode_str, port_type_str, rtp_number, rtcp_number);

  char *session_str = create_session_string(m_last_session_id);

  char *blocksize_str = create_blocksize_string(stream_using_tcp);

  add_field(transport_str);
  add_field(session_str);
  add_field(blocksize_str);
  SAFE_FREE(transport_str); SAFE_FREE(session_str); SAFE_FREE(blocksize_str);

  if (send_request(STR(cmd_url), "SETUP") > 0) {
    ResponseInfo ri;
    if (!recv_response(&ri) && ri.response_code == 200) {
      char *session_id = (char *) malloc(strlen(ri.session_parm_str) + 1);
      if (session_id) {
        do {
          if (!ri.session_parm_str ||
              sscanf(ri.session_parm_str, "%[^;]", session_id) != 1) {
            LOGE("Missing or bad \"Session:\" header");
            break;
          }
          subsession->set_session_id(session_id);
          SAFE_FREE(m_last_session_id); m_last_session_id = strdup(session_id);

          const char *after_session_id = ri.session_parm_str + strlen(session_id);
          int timeout_val;
          if (sscanf(after_session_id, ";timeout=%d", &timeout_val) == 1) {
            m_session_timeout_parameter = timeout_val;
          }
        } while (0);
        SAFE_FREE(session_id);
      } else {
        LOGE("malloc for session_id failed: %s", ERRNOMSG);
        return -1;
      }

      char *server_address_str;
      PortNumBits server_port_num;
      if (parse_transport_parms(ri.transport_parm_str,
                                server_address_str, server_port_num) < 0) {
        LOGE("Missing or bad \"Transport:\" header");
        return -1;
      }
      SAFE_FREE(subsession->connection_endpoint_name());
      subsession->connection_endpoint_name() = server_address_str;
      subsession->server_port_num() = server_port_num;

      m_stat = StateReady;
    }
  }
  return 0;
}

int RtspClient::parse_transport_parms(const char *parms_str,
                                      char *&server_address_str, PortNumBits &server_port_num)
{
  server_address_str = NULL;
  server_port_num = 0;
  if (!parms_str || !strlen(parms_str)) return -1;

  char *found_server_address_str = NULL;
  bool found_server_port_num = false;
  PortNumBits client_port_num = 0;
  bool found_client_port_num = false;
  bool is_multicast = true;
  char *found_destination_str = NULL;
  PortNumBits multicast_port_num_rtp, multicast_port_num_rtcp;
  bool found_multicast_port_num = false;
  unsigned rtp_cid, rtcp_cid;
  bool found_channel_ids = false;
  unsigned char rtp_channel_id, rtcp_channel_id;

  const char *fields = parms_str;
  char *field = (char *) malloc(strlen(fields) + 1);
  while (sscanf(fields, "%[^;]", field) == 1) {
    if (sscanf(field, "server_port=%hu", &server_port_num) == 1) {
      found_server_port_num = true;
    } else if (sscanf(field, "client_port=%hu", &client_port_num) == 1) {
      found_client_port_num = true;
    } else if (strncasecmp(field, "source=", 7) == 0) {
      SAFE_FREE(found_server_address_str);
      found_server_address_str = strdup(field + 7);
    } else if (sscanf(field, "interleaved=%u-%u", &rtp_cid, &rtcp_cid) == 2) {
      rtp_channel_id = (unsigned char ) rtp_cid;
      rtcp_channel_id = (unsigned char ) rtcp_cid;
      found_channel_ids = true;
    } else if (strcmp(field, "unicast") == 0) {
      is_multicast = false;
    } else if (strncasecmp(field, "destination=", 12) == 0) {
      SAFE_FREE(found_destination_str);
      found_destination_str = strdup(field + 12);
    } else if (sscanf(field, "port=%hu-%hu", &multicast_port_num_rtp, &multicast_port_num_rtcp) == 2 ||
               sscanf(field, "port=%hu", &multicast_port_num_rtp) == 1) {
      found_multicast_port_num = true;
    }

    fields += strlen(field);
    while (fields[0] == ';') ++fields; // Skip over all leading ';' chars
    if (fields[0] == '\0') break;
  }
  SAFE_FREE(field);

  if (is_multicast && found_destination_str && found_multicast_port_num) {
    SAFE_FREE(found_server_address_str);
    server_address_str = found_destination_str;
    server_port_num = multicast_port_num_rtp;
    return 0;
  }
  SAFE_FREE(found_destination_str);

  if (found_channel_ids || found_server_port_num || found_client_port_num) {
    if (found_client_port_num && !found_server_port_num)
      server_port_num = client_port_num;
    server_address_str = found_server_address_str;
    return 0;
  }

  SAFE_FREE(found_server_address_str);
  return -1;
}

static char *create_scale_string(float scale, float current_scale)
{
  char buf[100];

  if (scale == 1.0f && current_scale == 1.0f)
    buf[0] = '\0';
  else
    sprintf(buf, "Scale: %f", scale);

  return strdup(buf);
}

static char *create_range_string(double start, double end,
                                 const char *abs_start_time, const char *abs_end_time)
{
  char buf[100];

  if (abs_start_time != NULL) {
    if (abs_end_time == NULL)
      snprintf(buf, sizeof buf, "Range: clock=%s-", abs_start_time);
    else
      snprintf(buf, sizeof buf, "Range: clock=%s-%s", abs_start_time, abs_end_time);
  } else {
    if (start < 0)
      buf[0] = '\0';
    else if (end < 0)
      sprintf(buf, "Range: npt=%.3f-", start);
    else
      sprintf(buf, "Range: npt=%.3f-%.3f", start, end);
  }

  return strdup(buf);
}

int RtspClient::request_play(MediaSession *session,
                             double start, double end, float scale)
{
  if (!m_last_session_id) {
    LOGE("No RTSP session is currently in progress");
    return -1;
  }

  string cmd_url(generate_cmd_url(m_base_url, session));

  char *session_str = create_session_string(m_last_session_id);
  char *scale_str = create_scale_string(scale, session->scale());
  char *range_str = create_range_string(start, end, NULL, NULL);
  add_field(session_str);
  add_field(scale_str);
  add_field(range_str);
  SAFE_FREE(session_str); SAFE_FREE(scale_str); SAFE_FREE(range_str);

  if (send_request(STR(cmd_url), "PLAY") > 0) {
    ResponseInfo ri;
    if (!recv_response(&ri) && ri.response_code == 200) {
      m_stat = StatePlaying;
    }
  }
  return 0;
}

static bool is_absolute_url(char const* url) {
  while (*url != '\0' && *url != '/') {
    if (*url == ':') return true;
    ++url;
  }
  return false;
}

void RtspClient::construct_subsession_url(MediaSubsession const *subsession,
                                          const char *&prefix, const char *&separator, const char *&suffix)
{
  prefix = session_url(&subsession->parent_session());
  if (!prefix) prefix = "";

  suffix = subsession->control_path();
  if (!suffix) suffix = "";

  if (is_absolute_url(suffix)) {
    prefix = separator = "";
  } else {
    unsigned prefix_len = strlen(prefix);
    separator = (prefix_len == 0 || prefix[prefix_len-1] == '/' || suffix[0] == '/') ? "" : "/";
  }
}

const char *RtspClient::session_url(MediaSession const *session) const
{
  const char *url = session->control_path();
  if (url == NULL || strcmp(url, "*") == 0) url = m_base_url;
  return url;
}

int RtspClient::loop(volatile bool *watch_variable)
{
  return m_scheduler->do_event_loop(watch_variable);
}

void RtspClient::schedule_liveness_command()
{
  unsigned delay_max = m_session_timeout_parameter;
  if (!delay_max)
    delay_max = 60;

  const unsigned us_1st_part = delay_max*500000;
  unsigned u_seconds_to_delay;
  if (us_1st_part <= 1000000)
    u_seconds_to_delay = us_1st_part;
  else {
    const unsigned us_2nd_part = us_1st_part - 1000000;
    u_seconds_to_delay = us_1st_part + (us_2nd_part*random())%us_2nd_part;
  }

#ifdef XDEBUG
  LOGD("Will send_liveness_command() in %.2f secs",
      ((double) u_seconds_to_delay)/MILLION);
#endif

  if (m_liveness_command_task)
    m_scheduler->unschedule_delayed_task(m_liveness_command_task);
  m_liveness_command_task = m_scheduler->schedule_delayed_task(
      u_seconds_to_delay, send_liveness_command, this);
}

void RtspClient::send_liveness_command(void *client_data)
{
  RtspClient *rtsp_client = (RtspClient *) client_data;
  if (rtsp_client->m_server_supports_get_parameter)
    rtsp_client->request_get_parameter(continue_after_get_parameter);
  else
    rtsp_client->request_options(continue_after_options);
}

void RtspClient::continue_after_options(void *client_data)
{
  RtspClient *rtsp_client = (RtspClient *) client_data;
  if (!rtsp_client->m_server_supports_get_parameter)
    rtsp_client->schedule_liveness_command();
}

void RtspClient::continue_after_describe(void *client_data)
{
  RtspClient *rtsp_client = (RtspClient *) client_data;
  rtsp_client->schedule_liveness_command();
}

void RtspClient::stream_timer_handler(void *client_data)
{
  RtspClient *rtsp_client = (RtspClient *) client_data;
  rtsp_client->m_stream_timer_task = NULL;
  shutdown_stream(rtsp_client);
}

void RtspClient::shutdown_stream(RtspClient *rtsp_client)
{
  if (rtsp_client->m_stat == StatePlaying) {
    if (rtsp_client->request_teardown() < 0) {
      LOGE("Failed to send TEARDOWN command (cont)");
    }
    rtsp_client->m_scheduler->ask2quit();
  }
}

bool RtspClient::rtsp_option_is_supported(const char *command_name,
    const char *public_parm_str)
{
  return !!strcasestr(public_parm_str, command_name);
}

/////////////////////////////////////////////////////////////

std::string RtspUrl::to_string() const
{
  return sprintf_("rtsp://%s%s/%s",
                  username.empty() ? "" : STR(username + ":" + passwd + "@"),
                  STR(srvap.to_string()),
                  STR(stream_name));
}

RtspRecvBuf::RtspRecvBuf()
{
  reset();
}

int RtspRecvBuf::get_max_bufsz() const
{
  return sizeof(buf);
}

void RtspRecvBuf::reset()
{
  nread = 0;
  last_crlf = &buf[-3];
}

Rtsp::Rtsp() :
  m_stat(StateInit),
  m_cseq(0)
{
}

Rtsp::~Rtsp()
{
}

int Rtsp::parse_url(const string surl, RtspUrl &rtsp_url)
{
  const char *url = STR(surl), *p = strstr(url, "://");
  if (!p) {
    LOGE("RTSP url: No :// in url");
    return -1;
  }

  if (p-url!=4 || strncasecmp(url, "rtsp", 4)) {
    LOGE("Unknown protocol, not rtsp");
    return -1;
  }

  char tmp[2048];
  const char *from = p + 3;
  const char *colon_passwd_start = NULL;
  for (p = from; *p && *p != '/'; ++p) {
    if (*p == ':' && !colon_passwd_start)
      colon_passwd_start = p;
    else if (*p == '@') {
      if (!colon_passwd_start)
        colon_passwd_start = p;

      const char *username_start = from;
      int username_len = colon_passwd_start - username_start;
      strncpy(tmp, username_start, username_len);
      tmp[username_len] = '\0';
      rtsp_url.username = tmp;

      const char *passwd_start = colon_passwd_start;
      if (passwd_start < p) ++passwd_start;
      int passwd_len = p - passwd_start;
      strncpy(tmp, passwd_start, passwd_len);
      tmp[passwd_len] = '\0';
      rtsp_url.passwd = tmp;

      from = p + 1;
      break;
    }
  }

  int i;
  for (i = 0;
       from[i] && from[i] != ':' && from[i] != '/';
       ++i)
    tmp[i] = from[i];
  tmp[i] = '\0';
  rtsp_url.srvap.set_address(tmp);

  if (from[i] == ':') {
    for (p = from + i + 1, i = 0;
        *p && *p != '/';
        ++i, ++p)
      tmp[i] = *p;
    tmp[i] = '\0';
    rtsp_url.srvap.set_port(atoi(tmp));
    from = p;
  } else {
    rtsp_url.srvap.set_port(RTSP_PROTOCOL_PORT);
    from += i;
  }

  rtsp_url.stream_name = ++from;
  return 0;
}

void Rtsp::add_field(const std::string &field)
{
  if (field.empty()) return;
  m_fields.push_back(field+CRLF);
}

std::string Rtsp::field2string() const
{
  string str;
  FOR_VECTOR_CONST_ITERATOR(string, m_fields, it) {
    str += (*it);
  }
  return str;
}

}
