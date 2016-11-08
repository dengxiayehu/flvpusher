#include <xlog.h>
#include <get_bits.h>
#include <librtmp/log.h>

#include "rtmp_source.h"
#include "rtmp_sink.h"
#include "common/media_sink.h"
#include "common/config.h"
#include "flv/flv_parser.h"
#include "flv/tag_streamer.h"

//#define XDEBUG

using namespace xutil;

namespace flvpusher {

RtmpSource::RtmpSource(const std::string &input, MediaSink *&sink) :
  MediaPusher(input, sink),
  m_rtmp(NULL), m_buffer_time(RTMP_DEF_BUFTIME)
{
  m_vstrmer = new VideoTagStreamer();
  m_astrmer = new AudioTagStreamer();
  m_sstrmer = new ScriptTagStreamer();

  bzero(&m_info, sizeof(m_info));
}

RtmpSource::~RtmpSource()
{
  disconnect();

  SAFE_DELETE(m_vstrmer);
  SAFE_DELETE(m_astrmer);
  SAFE_DELETE(m_sstrmer);
}

int RtmpSource::prepare()
{
  int ret = TRUE;

  m_rtmp = RTMP_Alloc();
  if (!m_rtmp) {
    LOGE("RTMP_Alloc() failed for source: \"%s\"",
         STR(m_input));
    return -1;
  }

  RTMP_Init(m_rtmp);
  m_rtmp->Link.timeout = SOCK_TIMEOUT;

  RTMP_LogSetLevel(RTMP_LOGLEVEL);
  RTMP_LogSetCallback(rtmp_log);

  AVal parsed_host, parsed_app, parsed_playpath;
  unsigned int parsed_port = 0;
  int parsed_protocol = RTMP_PROTOCOL_UNDEFINED;
  AVal sockhost = { 0, 0 };

  if (!(ret = RTMP_ParseURL(STR(m_input), &parsed_protocol,
                            &parsed_host, &parsed_port,
                            &parsed_playpath, &parsed_app))) {
    LOGE("Couldn't parse the specified source: \"%s\"",
         STR(m_input));
    goto out;
  }

  {
    char str[512] = { 0 };
    AVal tcurl = { str, snprintf(str, sizeof(str)-1, "%s://%.*s:%d/%.*s",
                                 RTMPProtocolStringsLower[parsed_protocol],
                                 parsed_host.av_len, parsed_host.av_val,
                                 parsed_port,
                                 parsed_app.av_len, parsed_app.av_val) };

    RTMP_SetupStream(m_rtmp, parsed_protocol, &parsed_host, parsed_port,
                     &sockhost, &parsed_playpath, &tcurl, NULL, NULL,
                     &parsed_app, NULL, NULL, 0,
                     NULL, NULL, NULL, 0, 0, TRUE, SOCK_TIMEOUT);
  }

  RTMP_SetBufferMS(m_rtmp, m_buffer_time);

  if (!(ret = RTMP_Connect(m_rtmp, NULL))) {
    LOGE("RTMP_Connect failed for source: \"%s\"",
         STR(m_input));
    goto out;
  }

  if (!(ret = RTMP_ConnectStream(m_rtmp, 0))) {
    LOGE("RTMP_ConnectStream failed for source: \"%s\"",
         STR(m_input));
    goto out;
  }

  LOGI("Connect to rtmp source with url \"%s\" ok",
       STR(m_input));
out:
  SAFE_FREE(parsed_playpath.av_val);
  if (!ret)
    disconnect();
  return !ret ? -1 : 0;
}

int RtmpSource::disconnect()
{
  if (m_rtmp) {
    if (RTMP_IsConnected(m_rtmp)) {
      LOGI("Try to disconnect from source.. (url: %s)",
           STR(m_input));
    }

    RTMP_Close(m_rtmp);
    RTMP_Free(m_rtmp);
    m_rtmp = NULL;
  }
  return 0;
}

int RtmpSource::loop()
{
  if (prepare() < 0) {
    LOGE("RtmpSource's prepare() failed");
    return -1;
  }

  m_rtmp->m_read.timestamp = 0;
  m_rtmp->m_read.initialFrameType = 0;
  m_rtmp->m_read.nResumeTS = 0;
  m_rtmp->m_read.metaHeader = NULL;
  m_rtmp->m_read.initialFrame = NULL;
  m_rtmp->m_read.nMetaHeaderSize = 0;
  m_rtmp->m_read.nInitialFrameSize = 0;

  FLVParser parser;
  bool read_header = true;
  // Malloc play buffer on heap instead of stack
  char *buf = (char *) malloc(RTMP_MAX_PLAY_BUFSIZE);
  if (!buf) {
    LOGE("malloc for RTMP_MAX_PLAY_BUFSIZE failed: %s", ERRNOMSG);
    return -1;
  }
  double duration = 0;
  int nread = 0;
  do {
    int nprocessed = 0;
    nread = RTMP_Read(m_rtmp, buf, RTMP_MAX_PLAY_BUFSIZE);
    if (nread > 0) {
      if (duration <= 0)
        duration = RTMP_GetDuration(m_rtmp);
      if (duration > 0) {
        if (m_buffer_time < duration * 1000.0) {
          // Extra 5sec to make sure we've got enough
          m_buffer_time = (uint32_t) (duration * 1000.0) + 5000;

          LOGD("Detected that buffer time is less than duration, resetting to: %ums",
               m_buffer_time);
          RTMP_SetBufferMS(m_rtmp, m_buffer_time);
          RTMP_UpdateBufferMS(m_rtmp);
        }
      }

      if (read_header) { // Read flv file header first
        FLVParser::FLVHeader hdr;
        if ((nprocessed = parser.read_header(hdr,
                                             (uint8_t *) buf, nread)) < 0) {
          LOGE("Read FLV header failed");
          SAFE_FREE(buf);
          return -1;
        }
        nread -= nprocessed;
        read_header = false;
      }

      int offset = nprocessed;
      while (nread > 0) { // Cover multi-tag in one RTMP_Read()
        FLVParser::FLVTag *tag = parser.alloc_tag();
        if ((nprocessed = parser.read_tag(tag,
                                          (uint8_t *) (buf + offset), nread)) < 0) {
          LOGE("Read FLV tag failed");
          SAFE_FREE(buf);
          return -1;
        }
        nread -= nprocessed;
        offset += nprocessed;

        int32_t timestamp =
          (tag->hdr.timestamp_ext<<24) + VALUI24(tag->hdr.timestamp);

        if (timestamp < 0 && m_info.tm_offset == 0) {
            m_info.tm_offset = -timestamp;
        }
        timestamp += m_info.tm_offset;

        switch (tag->hdr.typ) {
          case FLVParser::TAG_VIDEO: {
            ++m_info.vrx;
            m_vstrmer->process(*tag);
            if (m_vstrmer->get_strm_length() == 0) {
              AVCDecorderConfigurationRecord avc_dcr =
                tag->dat.video.pkt.avc_dcr;
              SPS sps;
              GetBitContext gb;
              init_get_bits(&gb, avc_dcr.sps+1, 8 * (avc_dcr.sps_length-1));
              if (xmedia::h264_decode_sps(&gb, &sps) < 0) {
                LOGE("Parse sps failed");
                break;
              }
              m_info.w = 16*sps.mb_width;
              m_info.h = 16*sps.mb_height*(2-sps.frame_mbs_only_flag);
              break;
            }
            m_info.vcodec_id = tag->dat.video.codec_id;
            m_info.fps.check();
            m_info.vBC.check(m_vstrmer->get_strm_length()*8);
#ifdef XDEBUG
            LOGD("VIDEO timestamp is: %d", timestamp);
#endif
            uint32_t composition_time = VALUI24(tag->dat.video.pkt.composition_time);
            on_frame(timestamp,
                     m_vstrmer->get_strm(), m_vstrmer->get_strm_length(), 1,
                     composition_time);
            if (m_sink->send_video(timestamp,
                                   m_vstrmer->get_strm(), m_vstrmer->get_strm_length(),
                                   composition_time) < 0) {
              LOGE("Send video data to rtmpserver failed");
              set_interrupt(true);
            }
          } break;

          case FLVParser::TAG_AUDIO:
            ++m_info.arx;
            m_astrmer->process(*tag);
            if (m_astrmer->get_strm_length() == 0) {
              AudioSpecificConfig asc = tag->dat.audio.aac.asc;
              uint8_t profile, samplerate_idx, channel;
              if (parse_asc(asc,
                            profile, samplerate_idx, channel) < 0) {
                LOGE("Parse asc(%02x %02x) failed",
                     asc.dat[0], asc.dat[1]);
                break;
              }
              m_info.samplerate =
                atoi(samplerate_idx_to_str(samplerate_idx));
              m_info.channel = channel;
              break;
            }
            m_info.acodec_id = tag->dat.audio.sound_fmt;
            m_info.aBC.check(m_astrmer->get_strm_length()*8);
#ifdef XDEBUG
            LOGD("AUDIO timestamp is: %d", timestamp);
#endif
            on_frame(timestamp,
                     m_astrmer->get_strm(), m_astrmer->get_strm_length(), 0);
            if (m_sink->send_audio(timestamp,
                                   m_astrmer->get_strm(), m_astrmer->get_strm_length()) < 0) {
              LOGE("Send audio data to rtmpserver failed");
              set_interrupt(true);
            }
            break;

          case FLVParser::TAG_SCRIPT:
            m_sstrmer->process(*tag);
            if (m_sink->type() == MediaSink::RTMP_SINK &&
                !((RtmpSink *) m_sink)->send_rtmp_pkt(RTMP_PACKET_TYPE_INFO, 0,
                                                      m_sstrmer->get_strm(), m_sstrmer->get_strm_length())) {
              LOGE("Send metadata to rtmpserver failed (cont)");
            }
            break;

          default:
            break;
        }

        parser.free_tag(tag);
      }
    } else {
      LOGW("Rtmp zero read, maybe source disconnected");
    }
  } while (!interrupt_cb() &&
           nread > -1 &&
           RTMP_IsConnected(m_rtmp) && !RTMP_IsTimedout(m_rtmp));

  SAFE_FREE(buf);

  if (nread < 0)
    nread = m_rtmp->m_read.status;

  if (nread == -3)
    return 0;

  if (nread < 0)
    return -1;

  return 0;
}

}
