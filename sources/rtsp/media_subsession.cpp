#include <xutil.h>

#include "rtsp_client.h"
#include "media_subsession.h"
#include "media_session.h"
#include "rtp_interface.h"
#include "h264_video_rtp_source.h"
#include "mpeg4_generic_rtp_source.h"
#include "rtcp.h"

using namespace xutil;
using namespace std;

namespace flvpusher {

SDPAttribute::SDPAttribute(char const* str_value, bool value_is_hexadecimal) :
  m_str_value(strdup(str_value)),
  m_str_value_to_lower(NULL),
  m_value_is_hexadecimal(value_is_hexadecimal)
{
  if (!m_str_value) {
    m_int_value = 1;
  } else {
    int str_size = strlen(m_str_value) + 1;

    m_str_value_to_lower = (char *) malloc(str_size);
    if (!m_str_value_to_lower) {
      LOGE("malloc for m_str_value_to_lower failed: %s", ERRNOMSG);
      return;
    }
    for (int i = 0; i < str_size-1; ++i) m_str_value_to_lower[i] = tolower(m_str_value[i]);
    m_str_value_to_lower[str_size-1] = '\0';

    if (sscanf(m_str_value_to_lower, value_is_hexadecimal ? "%x" : "%d", &m_int_value) != 1) {
      m_int_value = 0;
    }
  }
} 
    
SDPAttribute::~SDPAttribute() {
  SAFE_FREE(m_str_value);
  SAFE_FREE(m_str_value_to_lower);
}

/////////////////////////////////////////////////////////////

MediaSubsession::MediaSubsession(MediaSession &parent) :
  m_parent(parent),
  m_client_port_num(0),
  m_server_port_num(0),
  m_saved_sdp_lines(NULL),
  m_medium_name(NULL),
  m_protocol_name(NULL),
  m_rtp_payload_format(0xFF),
  m_conn_endpoint_name(NULL),
  m_bandwidth(0),
  m_codec_name(NULL),
  m_rtp_timestamp_frequency(0),
  m_num_channels(1),
  m_multiplex_rtcp_with_rtp(false),
  m_control_path(NULL),
  m_play_start_time(0),
  m_play_end_time(0),
  m_abs_start_time(NULL),
  m_abs_end_time(NULL),
  m_source_filter_name(NULL),
  m_video_width(0), m_video_height(0),
  m_video_fps(0),
  m_rtp_socket(NULL), m_rtcp_socket(NULL),
  m_rtp_source(NULL),
  m_rtcp(NULL),
  m_session_id(NULL)
{
}

MediaSubsession::~MediaSubsession()
{
  SAFE_FREE(m_saved_sdp_lines);
  SAFE_FREE(m_medium_name);
  SAFE_FREE(m_protocol_name);
  SAFE_FREE(m_conn_endpoint_name);
  SAFE_FREE(m_codec_name);
  SAFE_FREE(m_control_path);
  SAFE_FREE(m_abs_start_time);
  SAFE_FREE(m_abs_end_time);
  SAFE_FREE(m_source_filter_name);
  SAFE_DELETE(m_rtp_socket);
  if (!m_multiplex_rtcp_with_rtp)
    SAFE_DELETE(m_rtcp_socket);
  SAFE_DELETE(m_rtp_source);
  SAFE_DELETE(m_rtcp);
  SAFE_FREE(m_session_id);
  FOR_MAP(m_attr_table, string, SDPAttribute *, it)
    SAFE_DELETE(MAP_VAL(it));
}

int MediaSubsession::parse_sdp_line_c(const char *sdp_line)
{
  char *conn_endpoint_name = parse_c_line(sdp_line);
  if (conn_endpoint_name) {
    SAFE_FREE(m_conn_endpoint_name);
    m_conn_endpoint_name = conn_endpoint_name;
    return 0;
  }
  return -1;
}

int MediaSubsession::parse_sdp_line_b(const char *sdp_line)
{
  return sscanf(sdp_line, "b=AS:%u", &m_bandwidth) == 1 ? 0 : -1;
}

int MediaSubsession::parse_sdp_attr_rtpmap(const char *sdp_line)
{
  int ret = -1;
  unsigned rtpmap_payload_format;
  char *codec_name = (char *) malloc(strlen(sdp_line) + 1);
  if (!codec_name) return -1;
  unsigned rtp_timestamp_frequency = 0;
  unsigned num_channels = 1;
  if (sscanf(sdp_line, "a=rtpmap: %u %[^/]/%u/%u",
             &rtpmap_payload_format, codec_name, &rtp_timestamp_frequency,
             &num_channels) == 4 ||
      sscanf(sdp_line, "a=rtpmap: %u %[^/]/%u",
             &rtpmap_payload_format, codec_name, &rtp_timestamp_frequency) == 3 ||
      sscanf(sdp_line, "a=rtpmap: %u %s",
             &rtpmap_payload_format, codec_name) == 2) {
    ret = 0;
    if (rtpmap_payload_format == m_rtp_payload_format) {
      for (char* p = codec_name; *p; ++p) *p = toupper(*p);
      SAFE_FREE(m_codec_name); m_codec_name = strdup(codec_name);
      m_rtp_timestamp_frequency = rtp_timestamp_frequency;
      m_num_channels = num_channels;
    }
  }
  SAFE_FREE(codec_name);
  return ret;
}

int MediaSubsession::parse_sdp_attr_rtcpmux(const char *sdp_line)
{
  if (strncmp(sdp_line, "a=rtcp-mux", 10) == 0) {
    m_multiplex_rtcp_with_rtp = true;
    return 0;
  }   
  return -1;
}

int MediaSubsession::parse_sdp_attr_control(const char *sdp_line)
{
  int ret = -1;
  char *control_path = (char *) malloc(strlen(sdp_line) + 1);
  if (sscanf(sdp_line, "a=control: %s", control_path) == 1) {
    ret = 0;
    SAFE_FREE(m_control_path); m_control_path = strdup(control_path);
  }
  SAFE_FREE(control_path);
  return ret;
}

static int parse_range_attr(const char *sdp_line,
                            char *&abs_start_time, char *&abs_end_time)
{
  int len = strlen(sdp_line);
  char *as = (char *) malloc(len);
  char *ae = (char *) malloc(len);
  if (!as || !ae) return -1;
  int res = sscanf(sdp_line, "a=range: clock = %[^-\r\n]-%[^\r\n]", as, ae);
  if (res == 2) {
    abs_start_time = as;
    abs_end_time = ae;
  } else if (res == 1) {
    abs_start_time = as;
    SAFE_FREE(ae);
  } else {
    SAFE_FREE(as); SAFE_FREE(ae);
    return -1;
  }
  return 0;
}

int MediaSubsession::parse_sdp_attr_range(const char *sdp_line)
{
  int ret = -1;
  double play_start_time;
  double play_end_time;
  if (!parse_range_attr(sdp_line, play_start_time, play_end_time)) {
    ret = 0;
    if (play_start_time > m_play_start_time) {
      m_play_start_time = play_start_time;
      if (play_start_time > m_parent.play_start_time()) {
        m_parent.play_start_time() = play_start_time;
      }
    }
    if (play_end_time > m_play_end_time) {
      m_play_end_time = play_end_time;
      if (play_end_time > m_parent.play_end_time()) {
        m_parent.play_end_time() = play_end_time;
      }
    }
  } else if (!parse_range_attr(sdp_line, _abs_start_time(), _abs_end_time())) {
    ret = 0;
  }
  return ret;
}

int MediaSubsession::parse_sdp_attr_fmtp(const char *sdp_line)
{
  do {
    if (strncmp(sdp_line, "a=fmtp:", 7) != 0) break; sdp_line += 7;
    while (isdigit(*sdp_line)) ++sdp_line;
    ++sdp_line;

    unsigned const sdp_line_len = strlen(sdp_line);
    char* name_str = (char *) malloc(sdp_line_len+1);
    char* value_str = (char *) malloc(sdp_line_len+1);
    while (*sdp_line != '\0' && *sdp_line != '\r' && *sdp_line != '\n') {
      sdp_line = skip_blank((char *) sdp_line);
      int res = sscanf(sdp_line, "%[^=; \t\r\n]=%[^; \t\r\n]", name_str, value_str);
      if (res >= 1) {
        for (char* c = name_str; *c != '\0'; ++c) *c = tolower(*c);

        if (res == 1) {
          set_attr(name_str);
        } else {
          set_attr(name_str, value_str);
        }
      }

      while (*sdp_line != '\0' && *sdp_line != '\r' && *sdp_line != '\n' && *sdp_line != ';') ++sdp_line;
      while (*sdp_line == ';') ++sdp_line;
    }
    SAFE_FREE(name_str); SAFE_FREE(value_str);
    return 0;
  } while (0);
  return -1;
}

int MediaSubsession::parse_sdp_attr_source_filter(const char *sdp_line)
{
  return parse_source_filter_attr(sdp_line, m_source_filter_name);
}

int MediaSubsession::parse_sdp_attr_x_dimensions(const char *sdp_line)
{
  int ret = -1;
  int width, height;
  if (sscanf(sdp_line, "a=x-dimensions:%d,%d", &width, &height) == 2) {
    ret = 0;
    m_video_width = (unsigned short) width;
    m_video_height = (unsigned short) height;
  } 
  return ret;
}

int MediaSubsession::parse_sdp_attr_framerate(const char *sdp_line)
{
  int ret = -1;
  float frate;
  int rate;
  if (sscanf(sdp_line, "a=framerate: %f", &frate) == 1 ||
      sscanf(sdp_line, "a=framerate:%f", &frate) == 1) {
    ret = 0;
    m_video_fps = (unsigned)frate;
  } else if (sscanf(sdp_line, "a=x-framerate: %d", &rate) == 1) {
    ret = 0;
    m_video_fps = (unsigned)rate;
  }               
  return ret;
}

int MediaSubsession::initiate(const std::string &own_ip)
{
  if (m_rtp_source) return 0;

  do {
    if (!m_codec_name) {
      LOGE("Codec is unspecified");
      break;
    }

    TaskScheduler *scheduler = parent_session().rtsp_client()->scheduler();
    AddressPort ap;
    struct in_addr temp_addr;
    temp_addr.s_addr = connection_endpoint_address();

    if (m_client_port_num != 0 && is_multicast_address(temp_addr.s_addr)) {
      const bool protocol_is_rtp = strcmp(m_protocol_name, "RTP");
      if (protocol_is_rtp && !m_multiplex_rtcp_with_rtp)
        m_client_port_num = m_client_port_num&~1;

      ap.set_address_port(STR(own_ip), m_client_port_num);
      m_rtp_socket = new RtpInterface(scheduler,
                                      connection_endpoint_name(), server_port_num());
      if (m_rtp_socket->open(ap) < 0) {
        LOGE("Failed to create RTP socket");
        break;
      }

      if (protocol_is_rtp) {
        if (m_multiplex_rtcp_with_rtp)
          m_rtcp_socket = m_rtp_socket;
        else {
          const PortNumBits rtcp_port_num = m_client_port_num|1;
          m_rtcp_socket = new RtpInterface(scheduler,
                                           connection_endpoint_name(), server_port_num()+1);
          ap.set_address_port(STR(own_ip), rtcp_port_num);
          m_rtcp_socket->open(ap);
        }
      }
    } else {
      bool success = false;
      for ( ; ; ) {
        m_rtp_socket = new RtpInterface(scheduler,
                                        connection_endpoint_name(), server_port_num());
        ap.set_address_port(STR(own_ip), 0);
        if (m_rtp_socket->open(ap) < 0) {
          LOGE("Unable to create RTP socket");
          break;
        }
        m_client_port_num = ap.get_port();

        if (m_multiplex_rtcp_with_rtp) {
          m_rtcp_socket = m_rtp_socket;
          success = true;
          break;
        }

        if ((m_client_port_num&1) != 0) {
          SAFE_DELETE(m_rtp_socket);
          continue;
        }

        PortNumBits rtcp_port_num = m_client_port_num|1;
        m_rtcp_socket = new RtpInterface(scheduler,
                                         connection_endpoint_name(), server_port_num()+1);
        ap.set_address_port(STR(own_ip), rtcp_port_num);
        if (m_rtcp_socket->open(ap) < 0) {
          SAFE_DELETE(m_rtcp_socket); SAFE_DELETE(m_rtp_socket);
          continue;
        } else {
          success = true;
          break;
        }
      }
      if (!success) break;
    }

    unsigned rtp_buf_size = m_bandwidth * 25 / 2;
    if (rtp_buf_size < 50 * 1024)
      rtp_buf_size = 50 * 1024;
    m_rtp_socket->increate_receive_buffer_to(rtp_buf_size);

    if (create_source_object() < 0) break;

    if (!m_rtp_source) {
      LOGE("Failed to create read source");
      break;
    }

    if (m_rtcp_socket) {
      m_rtcp = new Rtcp(parent_session().rtsp_client()->scheduler(),
                        m_rtcp_socket, m_parent.CNAME(), this);
      if (!m_rtcp) {
        LOGE("Failed to create RTCP instance");
        break;
      }
    }

    // Also auto-enable rtp's data receiving
    if (m_rtp_source->start_receiving() < 0)
      break;
    return 0;
  } while (0);

  m_client_port_num = 0;
  return -1;
}

void MediaSubsession::set_attr(const char *name, const char *value, bool value_is_hexadecimal)
{
  AttrTable::iterator it = m_attr_table.find(name);
  if (it != m_attr_table.end()) {
    value_is_hexadecimal = MAP_VAL(it)->value_is_hexadecimal();
    m_attr_table.erase(it);
    SAFE_DELETE(MAP_VAL(it));
  }
  SDPAttribute *new_attr = new SDPAttribute(value, value_is_hexadecimal);
  m_attr_table.insert(pair<string, SDPAttribute *>(name, new_attr));
}

int MediaSubsession::attr_val_int(const char *attr_name)
{
  AttrTable::iterator it = m_attr_table.find(attr_name);
  if (it != m_attr_table.end())
    return MAP_VAL(it)->int_value();
  return 0;
}

const char *MediaSubsession::attr_val_str2lower(const char *attr_name)
{
  AttrTable::iterator it = m_attr_table.find(attr_name);
  if (it != m_attr_table.end())
    return MAP_VAL(it)->str_value_to_lower();
  return "";
}

const char *MediaSubsession::attr_val_str(const char *attr_name)
{
  AttrTable::iterator it = m_attr_table.find(attr_name);
  if (it != m_attr_table.end())
    return MAP_VAL(it)->str_value();
  return "";
}

NetAddressBits MediaSubsession::connection_endpoint_address()
{
  do {
    const char *endpoint_string = connection_endpoint_name();
    if (!endpoint_string)
      endpoint_string = parent_session().connection_endpoint_name();
    if (!endpoint_string) break;

    NetAddressList addresses(endpoint_string);
    if (!addresses.num_addresses()) break;

    return *(NetAddressBits *)(addresses.first_address()->data());
  } while (0);
  return 0;
}

void MediaSubsession::set_session_id(const char *session_id)
{
  SAFE_FREE(m_session_id);
  m_session_id = strdup(session_id);
}

int MediaSubsession::create_source_object()
{
  do {
    if (!strcmp(m_protocol_name, "UDP")) {
      LOGE("A UDP-packetized stream is not supported");
      break;
    } else {
      if (!strcmp(m_codec_name, "H264")) {
        m_rtp_source = new H264VideoRTPSource(
            parent_session().rtsp_client()->scheduler(),
            m_rtp_socket,
            m_rtp_payload_format, m_rtp_timestamp_frequency,
            attr_val_str("sprop-parameter-sets"),
            parent_session().opaque());
      } else if (!strcmp(m_codec_name, "MPEG4-GENERIC")) {
        const char *fmtp_config = attr_val_str("config");
        if (!strlen(fmtp_config)) fmtp_config = attr_val_str("configuration");
        m_rtp_source = new MPEG4GenericRTPSource(
            parent_session().rtsp_client()->scheduler(),
            m_rtp_socket,
            m_rtp_payload_format, m_rtp_timestamp_frequency,
            m_medium_name, attr_val_str2lower("mode"),
            attr_val_unsigned("sizelength"),
            attr_val_unsigned("indexlength"),
            attr_val_unsigned("indexdeltalength"),
            fmtp_config,
            parent_session().opaque());
      } else {
        LOGE("RTP payload format \"%s\" unknown or not supported",
             m_codec_name);
        break;
      }
    }
    return 0;
  } while (0);
  return -1;
}

void MediaSubsession::close()
{
  TaskScheduler *scheduler = parent_session().rtsp_client()->scheduler();
  if (m_rtp_socket && m_rtp_socket->get_sockfd() != -1) {
    scheduler->turn_off_background_read_handling(m_rtp_socket->get_sockfd());
  }
  if (m_rtcp_socket && m_rtcp_socket->get_sockfd() != -1) {
    scheduler->turn_off_background_read_handling(m_rtcp_socket->get_sockfd());
  }
}

}
