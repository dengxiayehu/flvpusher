#include <cstdlib>

#include <librtmp/log.h>
#include <xlog.h>
#include <xnet.h>
#include <xutil.h>
#include <xmedia.h>

#include "rtmp_sink.h"
#include "common/config.h"
#include "common/raw_parser.h"

#define VIDEO_BODY_HEADER_LENGTH    16
#define VIDEO_PAYLOAD_OFFSET        5

//#define XDEBUG
//#define XDEBUG_TIMESTAMP

using namespace xutil;
using namespace xmedia;

namespace flvpusher {

RtmpSink::RtmpSink(const std::string &flvpath) :
  MediaSink(flvpath)
{
  bzero(&m_rt, sizeof(m_rt));
}

RtmpSink::~RtmpSink()
{
  // If live still exists, disconnect it
  disconnect();

  SAFE_FREE(m_rt.prev_pkt[0]);
  SAFE_FREE(m_rt.prev_pkt[1]);
}

MediaSink::Type RtmpSink::type() const
{
  return RTMP_SINK;
}

std::string RtmpSink::type_str() const
{
  return "rtmp";
}

int RtmpSink::connect(const std::string &liveurl)
{
  RTMPContext *rt = &m_rt;

  if (rt->rtmp) {
    LOGE("Disconnect rtmp then connect again");
    return -1;
  }

  rt->rtmp = RTMP_Alloc();
  if (!rt->rtmp) {
    LOGE("RTMP_Alloc() failed for liveurl: \"%s\"",
         liveurl.c_str());
    return -1;
  }

  RTMP_Init(rt->rtmp);
  rt->rtmp->Link.timeout = SOCK_TIMEOUT;

  RTMP_LogSetLevel(RTMP_LOGLEVEL);
  RTMP_LogSetCallback(rtmp_log);

  if (!RTMP_SetupURL(rt->rtmp,
                     const_cast<char *>(liveurl.c_str()))) {
    LOGE("RTMP_SetupURL() failed for liveurl: \"%s\"",
         liveurl.c_str());
    goto bail;
  }

  // Enable the ability of pushing flv to rtmpserver
  RTMP_EnableWrite(rt->rtmp);

  if (!RTMP_Connect(rt->rtmp, NULL)) {
    LOGE("RTMP_Connect failed for liveurl: \"%s\"",
         liveurl.c_str());
    goto bail;
  };

  if (!RTMP_ConnectStream(rt->rtmp, 0)) {
    LOGE("RTMP_ConnectStream failed for liveurl: \"%s\"",
         liveurl.c_str());
    goto bail;
  }

  m_url = liveurl;

  LOGI("Connect to rtmp server with url \"%s\" ok",
       m_url.c_str());
  return 0;

bail:
  disconnect();
  return -1;
}

int RtmpSink::disconnect()
{
  RTMPContext *rt = &m_rt;
  if (rt->rtmp) {
    if (RTMP_IsConnected(rt->rtmp)) {
      LOGI("Disconnect from rtmp server (url: %s)",
           m_url.c_str());
    }

    RTMP_Close(rt->rtmp);
    RTMP_Free(rt->rtmp);
    rt->rtmp = NULL;
  }
  return 0;
}

int RtmpSink::send_video(int32_t timestamp, byte *dat, uint32_t length,
                         uint32_t composition_time)
{
  if (m_vparser->process(dat, length) < 0) {
    LOGE("Process video failed");
    return -1;
  }

  byte *buf = (byte *) m_mem_holder.alloc(
      length + VIDEO_BODY_HEADER_LENGTH + 128 /*Just in case*/);
  byte *cur = buf + VIDEO_PAYLOAD_OFFSET;

  for (uint32_t idx=0; idx<m_vparser->get_nalu_num(); ++idx) {
    const byte *nalu_dat =
      m_vparser->get_nalu_data(idx);
    uint32_t nalu_length =
      m_vparser->get_nalu_length(idx);

    // Check whether startcode is there, remove it
    if (STARTCODE4(nalu_dat)) {
      nalu_dat += 4;
      nalu_length -= 4;
    } else if (STARTCODE3(nalu_dat)) {
      nalu_dat += 3;
      nalu_length -= 3;
    }

    // (X) Ignore sps & pps for it will send in avc_dcr-pkt (Marked)
    // Add sps & pps in I-frame
#if 0
    byte nalu_typ = (*nalu_dat)&0x1F;
    if (nalu_typ == 7 || nalu_typ == 8) {
      // Skip sps&pps in I-frame
      continue;
    }
#endif

    // Put nalu-length(4 bytes) before every nalu
    put_be32(cur, nalu_length);
    memcpy(cur + 4, nalu_dat, nalu_length);
    cur += (4 + nalu_length);
  }

  if (timestamp - m_vinfo.lts < -NEW_STREAM_TIMESTAMP_THESHO) {
    // Take this as a new video stream
    int32_t lvabs_ts = m_vinfo.lts + m_vinfo.tm_offset;
    int32_t laabs_ts = m_ainfo.lts + m_ainfo.tm_offset;
    int32_t shift_ts = laabs_ts - lvabs_ts;

    // Magic number guess it
    if (abs(shift_ts) <= NEW_STREAM_TIMESTAMP_THESHO*30) {
      if (shift_ts > 0) { // Audio frame comes first after new stream starts
        // Shift video frame's timestamp
        m_vinfo.tm_offset += shift_ts;
      } else {
        // Shift audio frame's timestamp
        m_ainfo.tm_offset += shift_ts;
      }
    }

    // Starts at the same timestamp with previous frame's
    m_vinfo.tm_offset += m_vinfo.lts;

#ifdef XDEBUG_TIMESTAMP
    LOGI("New video stream starts, atm_offset:%d, vtm_offset:%d",
         m_ainfo.tm_offset, m_vinfo.tm_offset);
#endif

    m_vinfo.need_cfg = true;
  }

  // Check whether need to send avc_dcr-pkt
  if (m_vinfo.need_cfg || m_vparser->sps_pps_changed()) {
    if (m_vparser->is_key_frame()) {
      byte avc_dcr_body[2048];
      int body_len = make_avc_dcr_body(avc_dcr_body,
                                       m_vparser->get_sps(), m_vparser->get_sps_length(),
                                       m_vparser->get_pps(), m_vparser->get_pps_length());
      if (!send_rtmp_pkt(RTMP_PACKET_TYPE_VIDEO,
                         timestamp+m_vinfo.tm_offset, avc_dcr_body, body_len)) {
        LOGE("Send video avc_dcr to rtmpserver failed");
        return -1;
      }

      m_vinfo.need_cfg = false;
    }
  }

  m_vinfo.lts = timestamp;

  int body_len = make_video_body(buf, cur-buf,
                                 m_vparser->is_key_frame(),
                                 composition_time);
  if (!send_rtmp_pkt(RTMP_PACKET_TYPE_VIDEO,
                     timestamp+m_vinfo.tm_offset, buf, body_len)) {
    LOGE("Send video data to rtmpserver failed");
    return -1;
  }

#ifdef XDEBUG_TIMESTAMP
  LOGI("Video timestamp: %d", timestamp+m_vinfo.tm_offset);
#endif
  return 0;
}

int RtmpSink::make_video_body(byte *buf, uint32_t dat_len, bool key_frame,
                              uint32_t composition_time)
{
  uint32_t idx = 0;

  buf[idx++] = key_frame ? 0x17 : 0x27;

  buf[idx++] = 0x01;

  put_be24(buf + idx, composition_time);
  return dat_len;
}

int RtmpSink::make_avc_dcr_body(byte *buf,
                                const byte *sps, uint32_t sps_len,
                                const byte *pps, uint32_t pps_len)
{
  uint32_t idx = 0;

  buf[idx++] = 0x17;

  buf[idx++] = 0x00;

  put_be24(buf + idx, 0);
  idx += 3;

  buf[idx++] = 0x01;
  buf[idx++] = sps[1];
  buf[idx++] = sps[2];
  buf[idx++] = sps[3];
  buf[idx++] = 0xFF;
  buf[idx++] = 0xE1;
  buf[idx++] = (byte) ((sps_len>>8)&0xFF);
  buf[idx++] = (byte) (sps_len&0xFF);
  memcpy(buf+idx, sps, sps_len);
  idx += sps_len;

  buf[idx++] = 0x01;
  buf[idx++] = (byte) ((pps_len>>8)&0xFF);
  buf[idx++] = (byte) (pps_len&0xFF);
  memcpy(buf+idx, pps, pps_len);
  idx += pps_len;

#ifdef XDEBUG
  LOGI("[avc_dcr] SPS: %02x %02x %02x %02x ... (%u bytes in total)",
       sps[0], sps[1], sps[2], sps[3], sps_len);
  LOGI("[avc_dcr] PPS: %02x %02x %02x %02x ... (%u bytes in total)",
       pps[0], pps[1], pps[2], pps[3], pps_len);
#endif
  return idx;
}

int RtmpSink::send_audio(int32_t timestamp, byte *dat, uint32_t length)
{
  if (m_aparser->process(dat, length) < 0) {
    LOGE("Process audio failed");
    return -1;
  }

  // Need to send asc before audio data
  // If timestamp backwards greatly, take it as a new flv audio stream
  if (timestamp == 0 ||       // Usually first audio frame comes
      timestamp - m_ainfo.lts < -NEW_STREAM_TIMESTAMP_THESHO || // New flv audio stream
      m_ainfo.need_cfg        // Ask to re-send asc
     ) {
    byte asc_body[4]; // asc-pkt payload is 4 bytes fixed
    make_asc_body(m_aparser->get_asc(), asc_body, sizeof(asc_body));

#ifdef XDEBUG
    AudioSpecificConfig asc;
    memcpy(asc.dat, m_aparser->get_asc(), 2);
    print_asc(asc);
#endif

    if (timestamp - m_ainfo.lts < -NEW_STREAM_TIMESTAMP_THESHO) {
      // Take this as a new audio stream
      int32_t lvabs_ts = m_vinfo.lts + m_vinfo.tm_offset;
      int32_t laabs_ts = m_ainfo.lts + m_ainfo.tm_offset;
      int32_t shift_ts = laabs_ts - lvabs_ts;

      if (abs(shift_ts) <= NEW_STREAM_TIMESTAMP_THESHO*30) {
        if (shift_ts > 0) { // Audio frame comes first after new stream starts
          // Shift video frame's timestamp
          m_vinfo.tm_offset += shift_ts;
        } else {
          // Shift audio frame's timestamp
          m_ainfo.tm_offset += shift_ts;
        }
      }

      m_ainfo.tm_offset += m_ainfo.lts;

#ifdef XDEBUG_TIMESTAMP
      LOGI("New audio stream starts, atm_offset:%d, vtm_offset:%d",
           m_ainfo.tm_offset, m_vinfo.tm_offset);
#endif
    }

    // NOTE: asc-pkt's timestamp is always 0
    if (!send_rtmp_pkt(RTMP_PACKET_TYPE_AUDIO,
                       timestamp+m_ainfo.tm_offset, asc_body, sizeof(asc_body))) {
      LOGE("Send asc-pkt failed");
      m_ainfo.need_cfg = true;
      return -1;
    } else {
      // If asc-pkt is successfully sent, reset the flag
      m_ainfo.need_cfg = false;
    }
  }

  m_ainfo.lts = timestamp;

  // 2 bytes for 0xAF 0x00/0x01 (normally is so)
  byte *buf = (byte *) m_mem_holder.alloc(length-7+2);
  int body_len = make_audio_body(dat+7, length-7, buf, length-7+2);
  if (!send_rtmp_pkt(RTMP_PACKET_TYPE_AUDIO,
                     timestamp+m_ainfo.tm_offset, buf, body_len)) {
    LOGE("Send audio data to rtmpserver failed");
    return -1;
  }

#ifdef XDEBUG_TIMESTAMP
  LOGI("Audio timestamp: %d", timestamp+m_ainfo.tm_offset);
#endif
  return 0;
}

int RtmpSink::make_asc_body(const byte asc[2], byte buf[], uint32_t len)
{
  buf[0] = 0xAF;
  buf[1] = 0x00;
  memcpy(buf+2, asc, 2);
  return 1 + 1 + 2;
}

// Note: dat is ADTS header removed
int RtmpSink::make_audio_body(const byte *dat, uint32_t dat_len,
                              byte buf[], uint32_t len)
{
  buf[0] = 0xAF;
  buf[1] = 0x01;
  memcpy(buf+2, dat, dat_len);
  return dat_len + 2;
}

byte RtmpSink::pkttyp2channel(byte typ)
{
  if (typ == RTMP_PACKET_TYPE_VIDEO) {
    return RTMP_VIDEO_CHANNEL;
  } else if (typ == RTMP_PACKET_TYPE_AUDIO || typ == RTMP_PACKET_TYPE_INFO) {
    return RTMP_AUDIO_CHANNEL;
  } else {
    return RTMP_SYSTEM_CHANNEL;
  }
}

bool RtmpSink::send_rtmp_pkt(int pkttype, uint32_t ts,
                             const byte *buf, uint32_t pktsize)
{
  if (m_flvmuxer.is_opened()) {
    if (m_flvmuxer.write_tag(pkttype, ts, buf, pktsize) < 0) {
      LOGE("Write tag to flv file \"%s\" failed (cont)",
           m_flvmuxer.get_path());
      // Fall through
    }
  }

  RTMPContext *rt = &m_rt;
#if defined (RTMP_SEND_FFMPEG) && (RTMP_SEND_FFMPEG != 0)
  int channel = RTMP_AUDIO_CHANNEL;

  if (pkttype == RTMP_PACKET_TYPE_VIDEO)
    channel = RTMP_VIDEO_CHANNEL;

  if (((pkttype == RTMP_PACKET_TYPE_VIDEO || pkttype == RTMP_PACKET_TYPE_AUDIO) && !ts) ||
      pkttype == RTMP_PACKET_TYPE_INFO) {
    if (rtmp_check_alloc_array(&rt->prev_pkt[1],
                               &rt->nb_prev_pkt[1], channel) < 0)
      return false;
    rt->prev_pkt[1][channel].channel_id = 0;
  }

  if (rtmp_packet_create(&rt->out_pkt, channel,
                         pkttype, ts, pktsize) < 0)
    return false;

  rt->out_pkt.extra = rt->rtmp->m_stream_id;
  memcpy(rt->out_pkt.data, buf, pktsize);
  if (rtmp_send_packet(rt, &rt->out_pkt, 0) < 0)
    return false;

  return true;
#else
  ::RTMPPacket rtmp_pkt;
  RTMPPacket_Reset(&rtmp_pkt);
  RTMPPacket_Alloc(&rtmp_pkt, pktsize);
  memcpy(rtmp_pkt.m_body, buf, pktsize);
  rtmp_pkt.m_packetType = pkttype;
  rtmp_pkt.m_nChannel = pkttyp2channel(pkttype);
  rtmp_pkt.m_headerType = RTMP_PACKET_SIZE_LARGE;
  rtmp_pkt.m_nTimeStamp = ts;
  rtmp_pkt.m_hasAbsTimestamp = 0;
  rtmp_pkt.m_nInfoField2 = rt->rtmp->m_stream_id;
  rtmp_pkt.m_nBodySize = pktsize;
  bool retval = RTMP_SendPacket(rt->rtmp, &rtmp_pkt, FALSE);
  RTMPPacket_Free(&rtmp_pkt);
  return retval;
#endif
}

int RtmpSink::rtmp_check_alloc_array(RTMPPacket **prev_pkt, int *nb_prev_pkt,
                                     int channel)
{
  int nb_alloc;
  RTMPPacket *ptr;
  if (channel < *nb_prev_pkt)
    return 0;

  nb_alloc = channel + 16;
  ptr = (RTMPPacket *) realloc(*prev_pkt, nb_alloc*sizeof(**prev_pkt));
  if (!ptr) {
    LOGE("realloc for prev_pkt array failed: %s", ERRNOMSG);
    return -1;
  }
  memset(ptr + *nb_prev_pkt, 0, (nb_alloc - *nb_prev_pkt)*sizeof(*ptr));
  *prev_pkt = ptr;
  *nb_prev_pkt = nb_alloc;
  return 0;
}

int RtmpSink::rtmp_packet_create(RTMPPacket *pkt, int channel_id, int type,
                                 int timestamp, int size)
{
  if (size) {
    pkt->data = (uint8_t *) malloc(size);
    if (!pkt->data) {
      LOGE("Create rtmp_packet failed: %s", ERRNOMSG);
      return -1;
    }
  }
  pkt->size       = size;
  pkt->channel_id = channel_id;
  pkt->type       = type;
  pkt->timestamp  = timestamp;
  pkt->extra      = 0;                     
  pkt->ts_field   = 0;
  return 0;
}

int RtmpSink::rtmp_send_packet(RTMPContext *rt, RTMPPacket *pkt, int track)
{
  int ret;

  ret = rtmp_packet_write(rt, pkt, rt->rtmp->m_outChunkSize,
                          &rt->prev_pkt[1], &rt->nb_prev_pkt[1]);
  rtmp_packet_destroy(pkt);
  return ret;
}

void RtmpSink::rtmp_packet_destroy(RTMPPacket *pkt)
{
  if (!pkt)
    return;
  SAFE_FREE(pkt->data);
  pkt->size = 0;
}

int RtmpSink::rtmp_packet_write(RTMPContext *rt, RTMPPacket *pkt, int chunk_size,
                                RTMPPacket **prev_pkt_ptr, int *nb_prev_pkt)
{
  uint8_t pkt_hdr[16], *p = pkt_hdr;
  int mode = RTMP_PS_TWELVEBYTES;
  int off = 0;
  int written = 0;
  int ret;
  RTMPPacket *prev_pkt;
  int use_delta;
  uint32_t timestamp;

  if ((ret = rtmp_check_alloc_array(prev_pkt_ptr, nb_prev_pkt,
                                    pkt->channel_id)) < 0)
    return ret;
  prev_pkt = *prev_pkt_ptr;

  use_delta = prev_pkt[pkt->channel_id].channel_id &&
    pkt->extra == prev_pkt[pkt->channel_id].extra &&
    pkt->timestamp >= prev_pkt[pkt->channel_id].timestamp;

  timestamp = pkt->timestamp;
  if (use_delta) {
    timestamp -= prev_pkt[pkt->channel_id].timestamp;
  }
  if (timestamp >= 0xFFFFFF) {
    pkt->ts_field = 0xFFFFFF;
  } else {
    pkt->ts_field = timestamp;
  }

  if (use_delta) {
    if (pkt->type == prev_pkt[pkt->channel_id].type &&
        pkt->size == prev_pkt[pkt->channel_id].size) {
      mode = RTMP_PS_FOURBYTES;
      if (pkt->ts_field == prev_pkt[pkt->channel_id].ts_field)
        mode = RTMP_PS_ONEBYTE;
    } else {
      mode = RTMP_PS_EIGHTBYTES;
    }
  }

  if (pkt->channel_id < 64) {
    *p++ = pkt->channel_id | (mode << 6);
  } else if (pkt->channel_id < 64 + 256) {
    *p++ = 0 | (mode << 6);
    *p++ = pkt->channel_id - 64;
  } else {
    *p++ = 1 | (mode << 6);
    p = put_be16(p, pkt->channel_id - 64);
  }
  if (mode != RTMP_PS_ONEBYTE) {
    p = put_be24(p, pkt->ts_field);
    if (mode != RTMP_PS_FOURBYTES) {
      p = put_be24(p, pkt->size);
      *p++ = pkt->type;
      if (mode == RTMP_PS_TWELVEBYTES) {
        *((uint32_t *)p) = pkt->extra;
        p += 4;
      }
    }
  }
  if (pkt->ts_field == 0xFFFFFF)
    p = put_be32(p, timestamp);

  // Save histroy
  prev_pkt[pkt->channel_id].channel_id = pkt->channel_id;
  prev_pkt[pkt->channel_id].type       = pkt->type;
  prev_pkt[pkt->channel_id].size       = pkt->size;
  prev_pkt[pkt->channel_id].timestamp  = pkt->timestamp;
  prev_pkt[pkt->channel_id].ts_field   = pkt->ts_field;
  prev_pkt[pkt->channel_id].extra      = pkt->extra;

  if ((ret = send_to_network(rt, pkt_hdr, p - pkt_hdr)) < 0)
    return ret;
  written = p - pkt_hdr + pkt->size;
  while (off < pkt->size) {
    int towrite = MIN(chunk_size, pkt->size - off);
    if ((ret = send_to_network(rt, pkt->data + off, towrite)) < 0)
      return ret;
    off += towrite;
    if (off < pkt->size) {  
      uint8_t marker = 0xC0 | pkt->channel_id;
      if ((ret = send_to_network(rt, &marker, 1)) < 0)
        return ret;
      written++;
    }
  }
  return written;
}

int RtmpSink::send_to_network(RTMPContext *rt, const uint8_t *buf, int size)
{
  int ret;

  do {
    ret = xnet::network_wait_fd(RTMP_Socket(rt->rtmp), 1, 100);
  } while (ret == EAGAIN && !interrupt_cb());

  if (ret)
    return ret;

  return ::send(RTMP_Socket(rt->rtmp), buf, size, MSG_NOSIGNAL);
}

}
