#include <xlog.h>

#include "media_session.h"
#include "media_subsession.h"
#include "rtsp_client.h"

using namespace xutil;

namespace flvpusher {

MediaSession::MediaSession(RtspClient *rtsp_client, void *opaque) :
  m_client(rtsp_client),
  m_sess_name(NULL),
  m_sess_desc(NULL),
  m_conn_endpoint_name(NULL),
  m_control_path(NULL),
  m_max_play_start_time(0.0f), m_max_play_end_time(0.0f),
  m_media_sess_type(NULL),
  m_source_filter_name(NULL),
  m_abs_start_time(NULL),
  m_abs_end_time(NULL),
  m_scale(1.0f),
  m_opaque(opaque)
{
  char CNAME[128] = {0};
  gethostname(CNAME, sizeof(CNAME));
  m_cname = strdup(CNAME);
}

MediaSession::~MediaSession()
{
  SAFE_FREE(m_sess_name);
  SAFE_FREE(m_sess_desc);
  SAFE_FREE(m_conn_endpoint_name);
  SAFE_FREE(m_control_path);
  SAFE_FREE(m_media_sess_type);
  SAFE_FREE(m_source_filter_name);
  SAFE_FREE(m_abs_start_time);
  SAFE_FREE(m_abs_end_time);
  SAFE_FREE(m_cname);

  FOR_VECTOR_ITERATOR(MediaSubsession *, m_subsessions, it) {
    SAFE_DELETE(*it);
  }
  m_subsessions.clear();
}

int MediaSession::initialize_with_sdp(const std::string &sdp)
{
  if (sdp.empty()) return -1;

  const char *sdp_line = STR(sdp);
  const char *next_sdp_line;
  for ( ; ; ) {
    if (parse_sdp_line(sdp_line, next_sdp_line) < 0) return -1;
    if (sdp_line[0] == 'm') break;
    sdp_line = next_sdp_line;
    if (!sdp_line) break;

    if (!parse_sdp_line_s(sdp_line)) continue;
    if (!parse_sdp_line_i(sdp_line)) continue;
    if (!parse_sdp_line_c(sdp_line)) continue;
    if (!parse_sdp_attr_control(sdp_line)) continue;
    if (!parse_sdp_attr_range(sdp_line)) continue;
    if (!parse_sdp_attr_type(sdp_line)) continue;
    if (!parse_sdp_attr_source_filter(sdp_line)) continue;
  }

  while (sdp_line != NULL) {
    MediaSubsession *subsession = create_new_media_subsession();
    if (!subsession) {
      LOGE("Unable to create new MediaSubsession");
      return -1;
    }

    char *medium_name = (char *) malloc(strlen(sdp_line) + 1);
    if (!medium_name) return -1;
    const char *protocol_name = NULL;
    unsigned payload_format;
    if ((sscanf(sdp_line, "m=%s %hu RTP/AVP %u", medium_name, &subsession->m_client_port_num, &payload_format) == 3 ||
         sscanf(sdp_line, "m=%s %hu/%*u RTP/AVP %u", medium_name, &subsession->m_client_port_num, &payload_format) == 3) &&
        payload_format <= 127) {
      protocol_name = "RTP";
    } else if ((sscanf(sdp_line, "m=%s %hu UDP %u", medium_name, &subsession->m_client_port_num, &payload_format) == 3 ||
                sscanf(sdp_line, "m=%s %hu udp %u", medium_name, &subsession->m_client_port_num, &payload_format) == 3 ||
                sscanf(sdp_line, "m=%s %hu RAW/RAW/UDP %u", medium_name, &subsession->m_client_port_num, &payload_format) == 3) &&
               payload_format <= 127) {
      protocol_name = "UDP";
    } else {
      char *sdp_line_str;
      if (!next_sdp_line) {
        sdp_line_str = (char *) sdp_line;
      } else {
        sdp_line_str = strdup(sdp_line);
        sdp_line_str[next_sdp_line-sdp_line] = '\0';
      }
      LOGE("Bad SDP \"m=\" line: %s", sdp_line_str);
      if (sdp_line_str != (char *) sdp_line) SAFE_FREE(sdp_line_str);
      SAFE_FREE(medium_name);
      SAFE_FREE(subsession);
      for ( ; ; ) {
        sdp_line = next_sdp_line;
        if (!sdp_line) break;
        if (parse_sdp_line(sdp_line, next_sdp_line) < 0) return -1;
        if (sdp_line[0] == 'm') break;
      }
      continue;
    }

    m_subsessions.push_back(subsession);

    subsession->m_server_port_num = subsession->m_client_port_num;

    const char *start = sdp_line;
    subsession->m_saved_sdp_lines = strdup(start);

    subsession->m_medium_name = strdup(medium_name);
    SAFE_FREE(medium_name);
    subsession->m_protocol_name = strdup(protocol_name);
    subsession->m_rtp_payload_format = payload_format;

    for ( ; ; ) {
      sdp_line = next_sdp_line;
      if (!sdp_line) break;
      if (parse_sdp_line(sdp_line, next_sdp_line) < 0) return -1;
      if (sdp_line[0] == 'm') break;
      if (!subsession->parse_sdp_line_c(sdp_line)) continue;
      if (!subsession->parse_sdp_line_b(sdp_line)) continue;
      if (!subsession->parse_sdp_attr_rtpmap(sdp_line)) continue;
      if (!subsession->parse_sdp_attr_rtcpmux(sdp_line)) continue;
      if (!subsession->parse_sdp_attr_control(sdp_line)) continue;
      if (!subsession->parse_sdp_attr_range(sdp_line)) continue;
      if (!subsession->parse_sdp_attr_fmtp(sdp_line)) continue;
      if (!subsession->parse_sdp_attr_source_filter(sdp_line)) continue;
      if (!subsession->parse_sdp_attr_x_dimensions(sdp_line)) continue;
      if (!subsession->parse_sdp_attr_framerate(sdp_line)) continue;
    }
    if (sdp_line) subsession->m_saved_sdp_lines[sdp_line - start] = '\0';

    if (!subsession->m_codec_name) {
      subsession->m_codec_name = lookup_payload_format(
          subsession->m_rtp_payload_format,
          subsession->m_rtp_timestamp_frequency,
          subsession->m_num_channels);
      if (!subsession->m_codec_name) {
        LOGE("Unknown codec name for RTP payload type",
             STR(sprintf_("%d", subsession->m_rtp_payload_format)));
        return -1;
      }
    }

    if (!subsession->m_rtp_timestamp_frequency) {
      subsession->m_rtp_timestamp_frequency =
        guess_rtp_timestamp_frequency(subsession->m_medium_name, subsession->m_codec_name);
    }
  }
  return 0;
}

int MediaSession::parse_sdp_line(const char *input_line, const char *&next_line)
{
  next_line = NULL;
  for (const char *ptr = input_line; *ptr; ++ptr) {
    if (*ptr == '\r' || *ptr == '\n') {
      ++ptr;
      while (*ptr == '\r' || *ptr == '\n') ++ptr;
      next_line = ptr;
      if (next_line[0] == '\0') next_line = NULL;
      break;
    }
  }

  if (input_line[0] == '\r' || input_line[0] == '\n') return 0;
  if (strlen(input_line) < 2 || input_line[1] != '=' ||
      input_line[0] < 'a' || input_line[0] > 'z') {
    LOGE("Invalid sdp line: ", input_line);
    return -1;
  }

  return 0;
}

int MediaSession::parse_sdp_line_s(const char *sdp_line)
{
  int ret = -1;
  char *buffer = (char *) malloc(strlen(sdp_line) + 1);
  if (!buffer) return -1;
  if (sscanf(sdp_line, "i=%[^\r\n]", buffer) == 1) {
    ret = 0;
    SAFE_FREE(m_sess_name);
    m_sess_name = strdup(buffer);
#ifdef XDEBUG
    LOGD("media_sess_name: %s", m_sess_name);
#endif
  }
  SAFE_FREE(buffer);
  return ret;
}

int MediaSession::parse_sdp_line_i(const char *sdp_line)
{
  int ret = -1;
  char *buffer = (char *) malloc(strlen(sdp_line) + 1);
  if (!buffer) return -1;
  if (sscanf(sdp_line, "i=%[^\r\n]", buffer) == 1) {
    ret = 0;
    SAFE_FREE(m_sess_desc);
    m_sess_desc = strdup(buffer);
#ifdef XDEBUG
    LOGD("sess_desc: %s", m_sess_desc);
#endif
  }
  SAFE_FREE(buffer);
  return ret;
}

char *parse_c_line(const char *sdp_line)
{
  char *retval = NULL;
  char *buffer = (char *) malloc(strlen(sdp_line) + 1);
  if (sscanf(sdp_line, "c=IN IP4 %[^/\r\n]", buffer) == 1)
    retval = strdup(buffer);
  SAFE_FREE(buffer);
  return retval;
}

int MediaSession::parse_sdp_line_c(const char *sdp_line)
{
  char *conn_endpoint_name = parse_c_line(sdp_line);
  if (conn_endpoint_name) {
    SAFE_FREE(m_conn_endpoint_name);
    m_conn_endpoint_name = conn_endpoint_name;
#ifdef XDEBUG
    LOGD("conn_endpoint_name: %s", m_conn_endpoint_name);
#endif
    return 0;
  }
  return -1;
}

int MediaSession::parse_sdp_attr_control(const char *sdp_line)
{
  int ret = -1;
  char *control_path = (char *) malloc(strlen(sdp_line) + 1);
  if (sscanf(sdp_line, "a=control: %s", control_path) == 1) {
    ret = 0;
    SAFE_FREE(m_control_path);
    m_control_path = strdup(control_path);
#ifdef XDEBUG
    LOGD("control_path: %s", m_control_path);
#endif
  }
  SAFE_FREE(control_path);
  return ret;
}

int parse_range_attr(const char *sdp_line,
                     double &start_time, double &end_time)
{
  int res = sscanf(sdp_line, "a=range: npt = %lg - %lg",
      &start_time, &end_time);
  if (res == 2) return 0;
  return -1;
}

int MediaSession::parse_sdp_attr_range(const char *sdp_line)
{
  int ret = -1;
  double play_start_time;
  double play_end_time;
  if (!parse_range_attr(sdp_line, play_start_time, play_end_time)) {
    ret = 0;
    if (play_start_time > m_max_play_start_time)
      m_max_play_start_time = play_start_time;
    if (play_end_time > m_max_play_end_time)
      m_max_play_end_time = play_end_time;
#ifdef XDEBUG
    LOGD("max_play_start_time: %lf, max_play_end_time: %lf",
         m_max_play_start_time, m_max_play_end_time);
#endif
  }
  return ret;
}

int MediaSession::parse_sdp_attr_type(const char *sdp_line)
{
  int ret = -1;
  char *buffer = (char *) malloc(strlen(sdp_line) + 1);
  if (sscanf(sdp_line, "a=type: %[^ \r\n]", buffer) == 1) {
    ret = 0;
    SAFE_FREE(m_media_sess_type);
    m_media_sess_type = strdup(buffer);
#ifdef XDEBUG
    LOGD("media_sess_type: %s", m_media_sess_type);
#endif
  }   
  SAFE_FREE(buffer);
  return ret;
}

int parse_source_filter_attr(const char *sdp_line, char *&source_filter_name)
{
  int ret = -1;
  char *source_name = (char *) malloc(strlen(sdp_line) + 1);
  if (!source_name) return -1;
  if (sscanf(sdp_line, "a=source-filter: incl IN IP4 %*s %s",
             source_name) == 1) {
    ret = 0;
    SAFE_FREE(source_filter_name);
    source_filter_name = strdup(source_name);
#ifdef XDEBUG
    LOGD("source_filter_name: %s", source_filter_name);
#endif
  }
  SAFE_FREE(source_name);
  return ret;
}

int MediaSession::parse_sdp_attr_source_filter(const char *sdp_line)
{
  return parse_source_filter_attr(sdp_line, m_source_filter_name);
}

MediaSession *MediaSession::create_new(RtspClient *rtsp_client, const char *sdp, void *opaque)
{
  MediaSession *new_session = new MediaSession(rtsp_client, opaque);
  if (new_session) {
    if (new_session->initialize_with_sdp(sdp) < 0) {
      SAFE_DELETE(new_session);
      return NULL;
    }
  }
  return new_session;
}

int MediaSession::setup_subsessions(bool stream_outgoing, bool stream_using_tcp)
{
  AddressPort ap;
  if (get_local_address_from_sockfd(m_client->get_sockfd(), ap) < 0)
    return -1;

  FOR_VECTOR_ITERATOR(MediaSubsession *, m_subsessions, it) {
    if ((*it)->initiate(ap.get_address()) < 0) {
      LOGE("Failed to initiate the \"%s/%s\" subsession (cont)",
           (*it)->medium_name(), (*it)->codec_name());
      continue;
    }
    if ((*it)->rtcp_is_muxed()) {
      LOGI("Initiated the \"%s/%s\" subsession (client port %d)",
           (*it)->medium_name(), (*it)->codec_name(), (*it)->client_port_num());
    } else {
      LOGI("Initiated the \"%s/%s\" subsession (client ports %d-%d)",
           (*it)->medium_name(), (*it)->codec_name(), (*it)->client_port_num(), (*it)->client_port_num()+1);
    }

    m_client->request_setup(*it, stream_outgoing, stream_using_tcp);
  }
  return 0;
}

int MediaSession::play_subsessions()
{
  if (abs_start_time()) {
    LOGE("The stream is indexed by 'absolute' time: %s, not supported",
         abs_start_time());
    return -1;
  } else {
    m_client->duration() = play_end_time() - play_start_time();
    return m_client->request_play(this);
  }
}

char *MediaSession::abs_start_time() const
{
  if (m_abs_start_time) return m_abs_start_time;

  FOR_VECTOR_CONST_ITERATOR(MediaSubsession *, m_subsessions, it) {
    if ((*it)->_abs_start_time()) return (*it)->_abs_start_time();
  }
  return NULL;
}

char *MediaSession::abs_end_time() const
{
  if (m_abs_end_time) return m_abs_end_time;

  FOR_VECTOR_CONST_ITERATOR(MediaSubsession *, m_subsessions, it) {
    if ((*it)->_abs_end_time()) return (*it)->_abs_end_time();
  }
  return NULL;
}

MediaSubsession *MediaSession::create_new_media_subsession()
{
  return new MediaSubsession(*this);
}

char *MediaSession::lookup_payload_format(unsigned char rtp_payload_type,
                                          unsigned &freq, unsigned &nchannel)
{
  char const* temp = NULL;
  switch (rtp_payload_type) {
    case 0:  {temp = "PCMU";    freq = 8000;  nchannel = 1; break;}
    case 2:  {temp = "G726-32"; freq = 8000;  nchannel = 1; break;}
    case 3:  {temp = "GSM";     freq = 8000;  nchannel = 1; break;}
    case 4:  {temp = "G723";    freq = 8000;  nchannel = 1; break;}
    case 5:  {temp = "DVI4";    freq = 8000;  nchannel = 1; break;}
    case 6:  {temp = "DVI4";    freq = 16000; nchannel = 1; break;}
    case 7:  {temp = "LPC";     freq = 8000;  nchannel = 1; break;}
    case 8:  {temp = "PCMA";    freq = 8000;  nchannel = 1; break;}
    case 9:  {temp = "G722";    freq = 8000;  nchannel = 1; break;}
    case 10: {temp = "L16";     freq = 44100; nchannel = 2; break;}
    case 11: {temp = "L16";     freq = 44100; nchannel = 1; break;}
    case 12: {temp = "QCELP";   freq = 8000;  nchannel = 1; break;}
    case 14: {temp = "MPA";     freq = 90000; nchannel = 1; break;}
    case 15: {temp = "G728";    freq = 8000;  nchannel = 1; break;}
    case 16: {temp = "DVI4";    freq = 11025; nchannel = 1; break;}
    case 17: {temp = "DVI4";    freq = 22050; nchannel = 1; break;}
    case 18: {temp = "G729";    freq = 8000;  nchannel = 1; break;}
    case 25: {temp = "CELB";    freq = 90000; nchannel = 1; break;}
    case 26: {temp = "JPEG";    freq = 90000; nchannel = 1; break;}
    case 28: {temp = "NV";      freq = 90000; nchannel = 1; break;}
    case 31: {temp = "H261";    freq = 90000; nchannel = 1; break;}
    case 32: {temp = "MPV";     freq = 90000; nchannel = 1; break;}
    case 33: {temp = "MP2T";    freq = 90000; nchannel = 1; break;}
    case 34: {temp = "H263";    freq = 90000; nchannel = 1; break;}
  };
  return strdup(temp);
}

unsigned MediaSession::guess_rtp_timestamp_frequency(
    const char *medium_name, const char *codec_name)
{
  if (strcmp(codec_name, "L16") == 0) return 44100;
  if (strcmp(codec_name, "MPA") == 0 ||
      strcmp(codec_name, "MPA-ROBUST") == 0 ||
      strcmp(codec_name, "X-MP3-DRAFT-00") == 0) return 90000;

  if (strcmp(medium_name, "video") == 0) return 90000;
  else if (strcmp(medium_name, "text") == 0) return 1000;
  return 8000;
}

}
