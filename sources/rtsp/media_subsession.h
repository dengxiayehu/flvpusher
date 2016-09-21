#ifndef _MEDIA_SUBSESSION_H_
#define _MEDIA_SUBSESSION_H_

#include <xnet.h>

using namespace xnet;

namespace flvpusher {

class SDPAttribute {
public:
  SDPAttribute(char const* str_value, bool value_is_hexadecimal);
  virtual ~SDPAttribute();

  char const* str_value() const { return m_str_value; }
  char const* str_value_to_lower() const { return m_str_value_to_lower; }
  int int_value() const { return m_int_value; }
  bool value_is_hexadecimal() const { return m_value_is_hexadecimal; }

private:
  char *m_str_value;
  char *m_str_value_to_lower;
  int m_int_value;
  bool m_value_is_hexadecimal;
};

class MediaSession;
class RtpInterface;
class MultiFramedRTPSource;
class Rtcp;

class MediaSubsession {
  friend class MediaSession;
public:
  MediaSubsession(MediaSession &parent);
  ~MediaSubsession();

  MediaSession &parent_session() { return m_parent; }
  MediaSession const &parent_session() const { return m_parent; }

  const char *control_path() const { return m_control_path; }
  const char *protocol_name() const { return m_protocol_name; }

  char *&_abs_start_time() { return m_abs_start_time; }
  char *&_abs_end_time() { return m_abs_end_time; }

  int parse_sdp_line_c(const char *sdp_line);
  int parse_sdp_line_b(const char *sdp_line);
  int parse_sdp_attr_rtpmap(const char *sdp_line);
  int parse_sdp_attr_rtcpmux(const char *sdp_line);
  int parse_sdp_attr_control(const char *sdp_line);
  int parse_sdp_attr_range(const char *sdp_line);
  int parse_sdp_attr_fmtp(const char *sdp_line);
  int parse_sdp_attr_source_filter(const char *sdp_line);
  int parse_sdp_attr_x_dimensions(const char *sdp_line);
  int parse_sdp_attr_framerate(const char *sdp_line);

  unsigned short client_port_num() const { return m_client_port_num; }
  unsigned char rtp_payload_format() const { return m_rtp_payload_format; }
  bool rtcp_is_muxed() const { return m_multiplex_rtcp_with_rtp; }
  const char *medium_name() const { return m_medium_name; }
  const char *codec_name() const { return m_codec_name; }

  int initiate(const std::string &own_ip);
  NetAddressBits connection_endpoint_address();
  char *&connection_endpoint_name() { return m_conn_endpoint_name; }

  void set_attr(const char *name, const char *value = NULL, bool value_is_hexadecimal = false);
  int attr_val_int(const char *attr_name);
  unsigned attr_val_unsigned(const char *attr_name)
  { return (unsigned) attr_val_int(attr_name); }
  const char *attr_val_str2lower(const char *attr_name);
  const char *attr_val_str(const char *attr_name);

  void set_session_id(const char *session_id);
  const char *session_id() const { return m_session_id; }

  int create_source_object();

  void close();

  unsigned short &client_port_num() { return m_client_port_num; }
  unsigned short &server_port_num() { return m_server_port_num; }

private:
  MediaSession &m_parent;
  unsigned short m_client_port_num;
  unsigned short m_server_port_num;
  char *m_saved_sdp_lines;
  char *m_medium_name;
  char *m_protocol_name;
  unsigned char m_rtp_payload_format;
  char *m_conn_endpoint_name;
  unsigned m_bandwidth;
  char *m_codec_name;
  unsigned m_rtp_timestamp_frequency;
  unsigned m_num_channels;
  bool m_multiplex_rtcp_with_rtp;
  char *m_control_path;
  double m_play_start_time;
  double m_play_end_time;
  char *m_abs_start_time;
  char *m_abs_end_time;
  typedef std::map<std::string, SDPAttribute *> AttrTable;
  AttrTable m_attr_table;
  char *m_source_filter_name;
  unsigned short m_video_width;
  unsigned short m_video_height;
  unsigned m_video_fps;
  RtpInterface *m_rtp_socket;
  RtpInterface *m_rtcp_socket;
  MultiFramedRTPSource *m_rtp_source;
  Rtcp *m_rtcp;
  char *m_session_id;
};

}

#endif /* end of _MEDIA_SUBSESSION_H_ */
