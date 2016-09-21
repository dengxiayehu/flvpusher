#ifndef _MEDIA_SESSION_H_
#define _MEDIA_SESSION_H_

#include <string>
#include <vector>

namespace flvpusher {

class RtspClient;
class MediaSubsession;

class MediaSession {
public:
  MediaSession(RtspClient *rtsp_client, void *opaque = NULL);
  ~MediaSession();

  int initialize_with_sdp(const std::string &sdp);
  int parse_sdp_line(const char *input_line, const char *&next_line);
  int parse_sdp_line_s(const char *sdp_line);
  int parse_sdp_line_i(const char *sdp_line);
  int parse_sdp_line_c(const char *sdp_line);
  int parse_sdp_attr_control(const char *sdp_line);
  int parse_sdp_attr_range(const char *sdp_line);
  int parse_sdp_attr_type(const char *sdp_line);
  int parse_sdp_attr_source_filter(const char *sdp_line);

  MediaSubsession *create_new_media_subsession();

  int setup_subsessions(bool stream_outgoing = false, bool stream_using_tcp = false);
  int play_subsessions();
  int enable_subsessions_data();

  static MediaSession *create_new(RtspClient *rtsp_client, const char *sdp, void *opaque = NULL);
  static char *lookup_payload_format(unsigned char rtp_payload_type,
                                     unsigned &freq, unsigned &nchannel);
  static unsigned guess_rtp_timestamp_frequency(const char *medium_name, const char *codec_name);

  double &play_start_time() { return m_max_play_start_time; }
  double &play_end_time() { return m_max_play_end_time; }
  const char *connection_endpoint_name() const { return m_conn_endpoint_name; };
  const char *control_path() const { return m_control_path; }
  char *abs_start_time() const;
  char *abs_end_time() const;
  float &scale() { return m_scale; }
  const char *CNAME() const { return m_cname; }

  RtspClient *rtsp_client() const { return m_client; }
  void *&opaque() { return m_opaque; }

private:
  RtspClient *m_client;
  char *m_sess_name;
  char *m_sess_desc;
  char *m_conn_endpoint_name;
  char *m_control_path;
  double m_max_play_start_time;
  double m_max_play_end_time;
  char *m_media_sess_type;
  char *m_source_filter_name;
  std::vector<MediaSubsession *> m_subsessions;
  char *m_abs_start_time;
  char *m_abs_end_time;
  float m_scale;
  char *m_cname;
  void *m_opaque;
};

int parse_source_filter_attr(const char *sdp_line, char *&source_filter_name);
char *parse_c_line(const char *sdp_line);
int parse_range_attr(const char *sdp_line,
                     double &start_time, double &end_time);

}

#endif /* end of _MEDIA_SESSION_H_ */
