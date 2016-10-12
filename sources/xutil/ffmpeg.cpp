#include "ffmpeg.h"

#include <limits.h>
#include <cstdlib>
#include <cassert>

#include <xlog.h>

//#define XDEBUG

namespace ffmpeg {

const uint8_t static mpeg4audio_channels[8] = {
  0, 1, 2, 3, 4, 5, 6, 8
};

const int static priv_mpeg4audio_sample_rates[16] = {
  96000, 88200, 64000, 48000, 44100, 32000,
  24000, 22050, 16000, 12000, 11025, 8000, 7350
};

enum { CODEC_PARSER_NUM = 2 };
static CodecParser parsers[] = {
  { CODEC_ID_AAC,  sizeof(AACParseContext), aac_parse_init,  aac_parse,  aac_parse_close,  },
  { CODEC_ID_H264, sizeof(H264Context),     h264_parse_init, h264_parse, h264_parse_close, },
};

int Packet::clone(Packet *pkt, bool reuse_buffer)
{
  if (!pkt)
    return -1;

  *this = *pkt;

  if (!reuse_buffer) {
    data = (uint8_t *) malloc(sizeof(uint8_t) * pkt->size);
    if (!data) return -1;
    memcpy(data, pkt->data, pkt->size);
  } else {
    pkt->data = NULL;
  }
  return 0;
}

AVRational av_mul_q(AVRational b, AVRational c)
{
  av_reduce(&b.num, &b.den,
            b.num * (int64_t) c.num, b.den * (int64_t) c.den,
            INT_MAX);
  return b;
}

int av_reduce(int *dst_num, int *dst_den, int64_t num, int64_t den, int64_t max)
{
  AVRational a0 = { 0, 1 }, a1 = { 1, 0 };
  int sign = (num < 0) ^ (den < 0);
  int64_t gcd = av_gcd(abs(num), abs(den));

  if (gcd) {
    num = abs(num) / gcd;
    den = abs(den) / gcd;
  }
  if (num <= max && den <= max) {
    a1 = (AVRational) { (int) num, (int) den };
    den = 0;
  }

  while (den) {
    uint64_t x        = num / den;
    int64_t next_den  = num - den * x;
    int64_t a2n       = x * a1.num + a0.num;
    int64_t a2d       = x * a1.den + a0.den;

    if (a2n > max || a2d > max) {
      if (a1.num) x = (max - a0.num) / a1.num;
      if (a1.den)
        x = MIN(x, (uint64_t) ((max - a0.den) / a1.den));

      if ((int64_t) (den * (2 * x * a1.den + a0.den)) > num * a1.den)
        a1 = (AVRational) { (int) (x * a1.num + a0.num), (int) (x * a1.den + a0.den) };
      break;
    }

    a0  = a1;
    a1  = (AVRational) { (int) a2n, (int) a2d };
    num = den;
    den = next_den;
  }
  assert(av_gcd(a1.num, a1.den) <= 1U);

  *dst_num = sign ? -a1.num : a1.num;
  *dst_den = a1.den;

  return den == 0;
}

int64_t av_gcd(int64_t a, int64_t b)
{
  if (b)
    return av_gcd(b, a % b);
  else
    return a;
}

int64_t av_rescale(int64_t a, int64_t b, int64_t c)
{
  return av_rescale_rnd(a, b, c, AV_ROUND_NEAR_INF);
}

int64_t av_rescale_rnd(int64_t a, int64_t b, int64_t c, enum AVRounding rnd)
{
  int64_t r = 0;

  if (c <= 0 || b < 0 || !((unsigned)(rnd&~AV_ROUND_PASS_MINMAX)<=5 && (rnd&~AV_ROUND_PASS_MINMAX)!=4))
    return INT64_MIN;

  if (rnd & AV_ROUND_PASS_MINMAX) {
    if (a == INT64_MIN || a == INT64_MAX)
      return a;
    int tmp = rnd - AV_ROUND_PASS_MINMAX;
    rnd = (AVRounding) tmp;
  }

  if (a < 0 && a != INT64_MIN)
    return -av_rescale_rnd(-a, b, c, (AVRounding) (rnd ^ ((rnd >> 1) & 1)));

  if (rnd == AV_ROUND_NEAR_INF)
    r = c / 2;
  else if (rnd & 1)
    r = c - 1;

  if (b <= INT_MAX && c <= INT_MAX) {
    if (a <= INT_MAX)
      return (a * b + r) / c;
    else
      return a / c * b + (a % c * b + r) / c;
  } else {
    uint64_t a0  = a & 0xFFFFFFFF;
    uint64_t a1  = a >> 32;
    uint64_t b0  = b & 0xFFFFFFFF;
    uint64_t b1  = b >> 32;
    uint64_t t1  = a0 * b1 + a1 * b0;
    uint64_t t1a = t1 << 32;
    int i;

    a0  = a0 * b0 + t1a;
    a1  = a1 * b1 + (t1 >> 32) + (a0 < t1a);
    a0 += r;
    a1 += a0 < (uint64_t) r;

    for (i = 63; i >= 0; i--) {
      a1 += a1 + ((a0 >> i) & 1);
      t1 += t1;
      if ((uint64_t) c <= a1) {
        a1 -= c;
        t1++;
      }
    }
    return t1;
  }
}

int64_t av_add_stable(AVRational ts_tb, int64_t ts, AVRational inc_tb, int64_t inc)
{
  int64_t m, d;

  if (inc != 1)
    inc_tb = av_mul_q(inc_tb, (AVRational) {(int) inc, 1});

  m = inc_tb.num * (int64_t)ts_tb.den;
  d = inc_tb.den * (int64_t)ts_tb.num;

  if (m % d == 0)
    return ts + m / d;
  if (m < d)
    return ts;

  {
    int64_t old = av_rescale_q(ts, ts_tb, inc_tb);
    int64_t old_ts = av_rescale_q(old, inc_tb, ts_tb);
    return av_rescale_q(old + 1, inc_tb, ts_tb) + (ts - old_ts);
  }
}

int64_t av_rescale_q(int64_t a, AVRational bq, AVRational cq)
{
  return av_rescale_q_rnd(a, bq, cq, AV_ROUND_NEAR_INF);
}

int64_t av_rescale_q_rnd(int64_t a, AVRational bq, AVRational cq, enum AVRounding rnd)
{
  int64_t b = bq.num * (int64_t)cq.den;
  int64_t c = cq.num * (int64_t)bq.den;
  return av_rescale_rnd(a, b, c, rnd);
}

void compute_frame_duration(FormatContext *s, int *pnum,
                            int *pden, Stream *st, CodecParserContext *pc, Packet *pkt)
{
  int frame_size;

  *pnum = 0;
  *pden = 0;
  switch (st->codec->codec_type) {
    case MEDIA_TYPE_AUDIO:
      if (st->codec->frame_size > 1 && pkt->size)
        frame_size = st->codec->frame_size;
      else
        frame_size = 0;
      if (frame_size <= 0 || st->codec->sample_rate <= 0)
        break;
      *pnum = frame_size;
      *pden = st->codec->sample_rate;
      break;

    case MEDIA_TYPE_VIDEO:
      *pnum = *pden = 0;
      break;

    default:
      break;
  }
}

Stream *format_new_stream(FormatContext *s)
{
  Stream *st;
  Stream **streams;

  if (s->nb_streams >= INT_MAX/sizeof(*streams))
    return NULL;
  streams = (Stream **) realloc(s->streams,
      (s->nb_streams + 1) * sizeof(*streams));
  if (!streams)
    return NULL;
  s->streams = streams;

  st = (Stream *) calloc(1, sizeof(Stream));
  if (!st)
    return NULL;

  st->codec = (CodecContext *) calloc(1, sizeof(CodecContext));
  if (!st->codec)
    return NULL;

  st->start_time = -1;
  st->first_dts = -1;
  st->cur_dts = -1;
  st->index = s->nb_streams;
  s->streams[s->nb_streams++] = st;
  return st;
}

void priv_set_pts_info(Stream *s, int pts_wrap_bits,
                       unsigned int pts_num, unsigned int pts_den)
{
  if (pts_num <= 0 || pts_den <= 0) {
    LOGE("Ignoring attempt to set invalid timebase %d/%d for st:%d",
         pts_num, pts_den, s->index);
    return;
  }
  s->time_base.num = pts_num;
  s->time_base.den = pts_den;
  s->pts_wrap_bits = pts_wrap_bits;
}

int has_codec_parameters(Stream *st)
{
  CodecContext *ctx = st->codec;

  if (ctx->codec_id == CODEC_ID_NONE)
    return 0;
  switch (ctx->codec_type) {
    case MEDIA_TYPE_AUDIO:
      if (!ctx->sample_rate) return 0;
      if (!ctx->channels) return 0;
      break;
    case MEDIA_TYPE_VIDEO:
      if (!ctx->width) return 0;
      if (!ctx->height) return 0;
      break;
    default:
      return 0;
  }
  return 1;
}

Packet *add_to_pktbuf(PacketList **packet_buffer,
                      Packet *pkt, PacketList **plast_pktl)
{
  PacketList *pktl = (PacketList *) calloc(1, sizeof(PacketList));
  if (!pktl)
    return NULL;

  if (*packet_buffer)
    (*plast_pktl)->next = pktl;
  else
    *packet_buffer = pktl;

  // Add the packet in the buffered packet list
  *plast_pktl = pktl;
  dup_packet(&pktl->pkt, pkt);
  return &pktl->pkt;
}

int read_from_packet_buffer(PacketList **pkt_buffer,
                            PacketList **pkt_buffer_end,
                            Packet      *pkt)
{
  PacketList *pktl;
  assert(*pkt_buffer);
  pktl        = *pkt_buffer;
  *pkt        = pktl->pkt;
  *pkt_buffer = pktl->next;
  if (!pktl->next)
    *pkt_buffer_end = NULL;
  SAFE_FREE(pktl);
  return 0;
}

void flush_packet_queue(FormatContext *s)
{
  free_packet_buffer(&s->parse_queue, &s->parse_queue_end);
  free_packet_buffer(&s->packet_buffer, &s->packet_buffer_end);
}

void free_packet_buffer(PacketList **pkt_buf, PacketList **pkt_buf_end)
{
  while (*pkt_buf) {
    PacketList *pktl = *pkt_buf;
    *pkt_buf = pktl->next;
    SAFE_FREE(pktl->pkt.data);
    SAFE_FREE(pktl);
  }
  *pkt_buf_end = NULL;
}

int dup_packet(Packet *dst, Packet *src)
{
  if (!dst || !src)
    return -1;

  *dst = *src;
  dst->data = (uint8_t *) malloc(src->size);
  if (!dst->data) {
    LOGE("malloc for Packet failed: %s", ERRNOMSG);
    return -1;
  }
  memcpy(dst->data, src->data, src->size);
  return 0;
}

CodecParserContext *parser_init(int codec_id)
{
  CodecParserContext *s = NULL;
  CodecParser *parser;
  int ret;

  if (codec_id == CODEC_ID_NONE)
    return NULL;

  for (unsigned i = 0; i < CODEC_PARSER_NUM; ++i) {
    parser = &parsers[i];
    if (parser->codec_id == codec_id)
      goto found;
  }
  LOGE("No parser with codec id: %d", codec_id);
  return NULL;

found:
  s = (CodecParserContext *) calloc(1, sizeof(CodecParserContext));
  if (!s)
    goto err_out;
  s->parser = parser;
  s->priv_data = calloc(1, parser->priv_data_size);
  if (!s->priv_data)
    goto err_out;
  s->fetch_timestamp = 1;
  if (parser->parser_init) {
    ret = parser->parser_init(s);
    if (ret != 0)
      goto err_out;
  }
  s->key_frame = -1;
  return s;

err_out:
  if (s) {
    SAFE_FREE(s->priv_data);
  }
  SAFE_FREE(s);
  return NULL;
}

void parser_close(CodecParserContext *s)
{
  if (s) {
    if (s->parser->parser_close)
      s->parser->parser_close(s);
    SAFE_FREE(s->priv_data);
    SAFE_FREE(s);
  }
}

int parse_packet(FormatContext *s, Packet *pkt, int stream_index)
{
  Packet out_pkt, flush_pkt;
  Stream *st = s->streams[stream_index];
  uint8_t *data = pkt ? pkt->data : NULL;
  int size = pkt ? pkt->size : 0;
  int ret = 0, got_output = 0;

  if (!pkt) {
    pkt = &flush_pkt;
    got_output = 1;
  }

  while (size > 0 || (pkt == &flush_pkt && got_output)) {
    int len;

    bzero(&out_pkt, sizeof(out_pkt));
    len = parser_parse2(st->parser, st->codec,
                        &out_pkt.data, &out_pkt.size, data, size,
                        pkt->pts, pkt->dts, pkt->pos);

    pkt->pts = pkt->dts = -1;
    pkt->pos = -1;
    // Increment read pointer
    data += len;
    size -= len;

    got_output = !!out_pkt.size;

    if (!out_pkt.size)
      continue;

    out_pkt.stream_index = st->index;
    out_pkt.pts = st->parser->pts;
    out_pkt.dts = st->parser->dts;
    out_pkt.pos = st->parser->pos;

    compute_pkt_fields(s, st, st->parser, &out_pkt);

    if (!add_to_pktbuf(&s->parse_queue, &out_pkt, &s->parse_queue_end)) {
      SAFE_FREE(out_pkt.data);
      ret = -1;
      goto fail;
    }
  }

  // End of the stream => close and free the parser
  if (pkt == &flush_pkt) {
    parser_close(st->parser);
    st->parser = NULL;
  }

fail:
  SAFE_FREE(pkt->data);
  return ret;
}

int parser_parse2(CodecParserContext *s,
                  CodecContext *avctx,
                  uint8_t **poutbuf, int *poutbuf_size,
                  const uint8_t *buf, int buf_size,
                  int64_t pts, int64_t dts, int64_t pos)
{
  int index;
  unsigned i;
  uint8_t dummy_buf[INPUT_BUFFER_PADDING_SIZE];

  if (!(s->flags & PARSER_FLAG_FETCHED_OFFSET)) {
    s->next_frame_offset =
    s->cur_offset        = pos;
    s->flags            |= PARSER_FLAG_FETCHED_OFFSET;
  }

  if (buf_size == 0) {
    // Padding is always necessary even if EOF, so we add it here
    memset(dummy_buf, 0, sizeof(dummy_buf));
    buf = dummy_buf;
  } else if (s->cur_offset + buf_size != s->cur_frame_end[s->cur_frame_start_index]) {
    // Add a new packet descriptor
    i = (s->cur_frame_start_index + 1) & (PARSER_PTS_NB - 1);
    s->cur_frame_start_index = i;
    s->cur_frame_offset[i]   = s->cur_offset;
    s->cur_frame_end[i]      = s->cur_offset + buf_size;
    s->cur_frame_pts[i]      = pts;
    s->cur_frame_dts[i]      = dts;
    s->cur_frame_pos[i]      = pos;
  }

  if (s->fetch_timestamp) {
    s->fetch_timestamp = 0;
    s->last_pts        = s->pts;
    s->last_dts        = s->dts;
    s->last_pos        = s->pos;
    fetch_timestamp(s, 0, 0);
  }

  // WARNING: the returned index can be negative
  index = s->parser->parser_parse(s, avctx, (const uint8_t **) poutbuf,
                                  poutbuf_size, buf, buf_size);

  // Update the file pointer
  if (*poutbuf_size) {
    // Fill the data for the current frame
    s->frame_offset = s->next_frame_offset;

    // Offset of the next frame
    s->next_frame_offset = s->cur_offset + index;
    s->fetch_timestamp   = 1;
  }
  if (index < 0)
    index = 0;
  s->cur_offset += index;
  return index;
}

void compute_pkt_fields(FormatContext *s, Stream *st,
                        CodecParserContext *pc, Packet *pkt)
{
  int num, den;
  AVRational duration;

  duration = av_mul_q((AVRational) { pkt->duration, 1 }, st->time_base);
  if (pkt->duration == 0) {
    compute_frame_duration(s, &num, &den, st, pc, pkt);
    if (den && num) {
      duration = (AVRational) {num, den};
      pkt->duration = av_rescale_rnd(1,
                                     num * (int64_t) st->time_base.den,
                                     den * (int64_t) st->time_base.num,
                                     AV_ROUND_DOWN);
    }
  }

  if (pkt->pts != -1 ||
      pkt->dts != -1 ||
      pkt->duration) {
    if (st->start_time == -1 ||
        (pkt->pts >= 0 && st->start_time > pkt->pts)) {
      st->start_time = pkt->pts;
    }
    if (pkt->pts == -1)
      pkt->pts = st->cur_dts;
    if (pkt->dts == -1)
      pkt->dts = pkt->pts;
    if (st->first_dts == -1)
      st->first_dts = pkt->dts;
    if (pkt->dts != -1)
      st->cur_dts = av_add_stable(st->time_base, pkt->dts, duration, 1);
  }
}

void fetch_timestamp(CodecParserContext *s, int off, int remove)
{
  int i;

  s->dts    =
  s->pts    = -1;
  s->pos    = -1;
  s->offset = 0;
  for (i = 0; i < PARSER_PTS_NB; i++) {
    if (s->cur_offset + off >= s->cur_frame_offset[i] &&
        (s->frame_offset < s->cur_frame_offset[i] ||
         (!s->frame_offset && !s->next_frame_offset)) && // first field/frame
        // check disabled since MPEG-TS does not send complete PES packets
        /*s->next_frame_offset + off <*/  s->cur_frame_end[i]){

      s->dts    = s->cur_frame_dts[i];
      s->pts    = s->cur_frame_pts[i];
      s->pos    = s->cur_frame_pos[i];
      s->offset = s->next_frame_offset - s->cur_frame_offset[i];
      if (remove)
        s->cur_frame_offset[i] = INT64_MAX;
      if (s->cur_offset + off < s->cur_frame_end[i])
        break;
    }
  }
}

int aac_parse_init(CodecParserContext *s1)
{
  AACParseContext *s = (AACParseContext *) s1->priv_data;
  s->header_size = AAC_ADTS_HEADER_SIZE;
  s->sync = aac_sync;
  return 0;
}

int aac_parse(CodecParserContext *s1,
              CodecContext *avctx,
              const uint8_t **poutbuf, int *poutbuf_size,
              const uint8_t *buf, int buf_size)
{
  AACParseContext *s = (AACParseContext *) s1->priv_data;
  ParseContext *pc = &s->pc;
  int len, i;
  int new_frame_start;

get_next:
  i = END_NOT_FOUND;
  if (s->remaining_size <= buf_size) {
    if (s->remaining_size && !s->need_next_header) {
      i = s->remaining_size;
      s->remaining_size = 0;
    } else { // We need a header first
      len = 0;
      for (i = s->remaining_size; i < buf_size; ++i) {
        s->state = (s->state<<8) + buf[i];
        if((len = s->sync(s->state, s, &s->need_next_header, &new_frame_start)))
          break;
      }
      if (len <= 0) {
        i = END_NOT_FOUND;
      } else {
        s->state = 0;
        i-= s->header_size -1;
        s->remaining_size = len;
        if(!new_frame_start || pc->index + i <= 0){
          s->remaining_size += i;
          goto get_next;
        }
      }
    }
  }

  if (combine_frame(pc, i, &buf, &buf_size) < 0) {
    s->remaining_size -= MIN(s->remaining_size, buf_size);
    *poutbuf = NULL;
    *poutbuf_size = 0;
    return buf_size;
  }

  *poutbuf = buf;
  *poutbuf_size = buf_size;

  // Update codec info
  if (s->codec_id)
    avctx->codec_id = s->codec_id;

  // Return the info we have already known
  avctx->bit_rate = s->bit_rate;
  avctx->sample_rate = s->sample_rate;
  avctx->channels = s->channels;
  if (avctx->codec_id == CODEC_ID_AAC) {
    avctx->frame_size = 1024; // AAC's frame_size is 1024 fixed
  }
  return i;
}

void aac_parse_close(CodecParserContext *s)
{
  ParseContext *pc = (ParseContext *) s->priv_data;

  SAFE_FREE(pc->buffer);
}

int h264_parse_init(CodecParserContext *s)
{
  H264Context *h = (H264Context *) s->priv_data;
  h->nal_unit_type = -1;
  h->nal_length_size = 4;
  return 0;
}

int h264_parse(CodecParserContext *s,
               CodecContext *avctx,
               const uint8_t **poutbuf, int *poutbuf_size,
               const uint8_t *buf, int buf_size)
{
  H264Context *h = (H264Context *) s->priv_data;

  if (!h->got_first) {
    h->got_first = 1;
    h->avctx = avctx;
  }

  parse_nal_units(s, avctx, buf, buf_size);

  *poutbuf = buf;
  *poutbuf_size = buf_size;
  return buf_size;
}

void h264_parse_close(CodecParserContext *s)
{
  H264Context *h = (H264Context *) s->priv_data;

  for (unsigned i = 0; i < 2; ++i) {
    SAFE_FREE(h->rbsp_buffer[i]);
  }
}

int aac_sync(uint64_t state, AACParseContext *hdr_info,
             int *need_next_header, int *new_frame_start)
{
#define BSWAP16C(x) (((x) << 8 & 0xff00)  | ((x) >> 8 & 0x00ff))
#define BSWAP32C(x) (BSWAP16C(x) << 16 | BSWAP16C((x) >> 16))
#define BSWAP64C(x) (BSWAP32C(x) << 32 | BSWAP32C((x) >> 32))

  GetBitContext bits;
  AACADTSHeaderInfo hdr;
  int size;
  union {
    uint64_t u64;
    uint8_t  u8[8 + INPUT_BUFFER_PADDING_SIZE];
  } tmp;

  bzero(&tmp, sizeof(tmp));
  tmp.u64 = BSWAP64C(state);
  init_get_bits(&bits,
                tmp.u8+8-AAC_ADTS_HEADER_SIZE, AAC_ADTS_HEADER_SIZE*8);

  if ((size = priv_aac_parse_header(&bits, &hdr)) < 0)
    return 0;
  *need_next_header = 0;
  *new_frame_start  = 1;
  hdr_info->sample_rate = hdr.sample_rate;
  hdr_info->channels    = mpeg4audio_channels[hdr.chan_config];
  hdr_info->samples     = hdr.samples;
  hdr_info->bit_rate    = hdr.bit_rate;
  return size;

#undef BSWAP16C
#undef BSWAP32C
#undef BSWAP64C
}

int combine_frame(ParseContext *pc, int next,
                  const uint8_t **buf, int *buf_size)
{
  if (pc->overread) {
#ifdef DEBUG
    LOGD("overread %d, state:%X next:%d index:%d o_index:%d",
         pc->overread, pc->state, next, pc->index, pc->overread_index);
    LOGD("%X %X %X %X",
         (*buf)[0], (*buf)[1], (*buf)[2], (*buf)[3]);
#endif
  }

  // Copy overread bytes from last frame into buffer.
  for (; pc->overread > 0; pc->overread--) {
    pc->buffer[pc->index++] = pc->buffer[pc->overread_index++];
  }

  // Flush remaining if EOF
  if (!*buf_size && next == END_NOT_FOUND)
    next = 0;

  pc->last_index = pc->index;

  // Copy into buffer end return
  if (next == END_NOT_FOUND) {
    void *new_buffer = realloc(pc->buffer,
                               *buf_size + pc->index + INPUT_BUFFER_PADDING_SIZE);

    if (!new_buffer) {
      LOGE("realloc for pc->buffer failed: %s", ERRNOMSG);
      pc->index = 0;
      return -1;
    }
    pc->buffer = (uint8_t *) new_buffer;
    memcpy(&pc->buffer[pc->index], *buf, *buf_size);
    pc->index += *buf_size;
    return -1;
  }

  *buf_size          =
    pc->overread_index = pc->index + next;

  // Append to buffer
  if (pc->index) {
    void *new_buffer = realloc(pc->buffer,
                               next + pc->index + INPUT_BUFFER_PADDING_SIZE);
    if (!new_buffer) {
      pc->overread_index = pc->index = 0;
      LOGE("realloc for pc->buffer failed: %s", ERRNOMSG);
      return -1;
    }
    pc->buffer = (uint8_t *) new_buffer;
    if (next > -INPUT_BUFFER_PADDING_SIZE)
      memcpy(&pc->buffer[pc->index], *buf, next + INPUT_BUFFER_PADDING_SIZE);
    pc->index = 0;
    *buf      = pc->buffer;
  }

  // Store overread bytes
  for (; next < 0; next++) {
    pc->state   = pc->state   << 8 | pc->buffer[pc->last_index + next];
    pc->state64 = pc->state64 << 8 | pc->buffer[pc->last_index + next];
    pc->overread++;
  }

  if (pc->overread) {
#ifdef DEBUG
    LOGD("overread %d, state:%X next:%d index:%d o_index:%d",
         pc->overread, pc->state, next, pc->index, pc->overread_index);
    LOGD("%X %X %X %X",
         (*buf)[0], (*buf)[1], (*buf)[2], (*buf)[3]);
#endif
  }

  return 0;
}

int priv_aac_parse_header(GetBitContext *gbc, AACADTSHeaderInfo *hdr)
{
  int size, rdb, ch, sr;
  int aot, crc_abs;

  if (get_bits(gbc, 12) != 0xfff)
    return -1;

  skip_bits1(gbc);             /* id */
  skip_bits(gbc, 2);           /* layer */
  crc_abs = get_bits1(gbc);    /* protection_absent */
  aot     = get_bits(gbc, 2);  /* profile_objecttype */
  sr      = get_bits(gbc, 4);  /* sample_frequency_index */
  if (!priv_mpeg4audio_sample_rates[sr])
    return -1;
  skip_bits1(gbc);             /* private_bit */
  ch = get_bits(gbc, 3);       /* channel_configuration */

  skip_bits1(gbc);             /* original/copy */
  skip_bits1(gbc);             /* home */

  /* adts_variable_header */
  skip_bits1(gbc);             /* copyright_identification_bit */
  skip_bits1(gbc);             /* copyright_identification_start */
  size = get_bits(gbc, 13);    /* aac_frame_length */
  if (size < AAC_ADTS_HEADER_SIZE)
    return -1;

  skip_bits(gbc, 11);          /* adts_buffer_fullness */
  rdb = get_bits(gbc, 2);      /* number_of_raw_data_blocks_in_frame */

  hdr->object_type    = aot + 1;
  hdr->chan_config    = ch;
  hdr->crc_absent     = crc_abs;
  hdr->num_aac_frames = rdb + 1;
  hdr->sampling_index = sr;
  hdr->sample_rate    = priv_mpeg4audio_sample_rates[sr];
  hdr->samples        = (rdb + 1) * 1024;
  hdr->bit_rate       = size * 8 * hdr->sample_rate / hdr->samples;

  return size;
}

int parse_nal_units(CodecParserContext *s,
                    CodecContext *avctx,
                    const uint8_t * const buf, int buf_size)
{
  H264Context *h = (H264Context *) s->priv_data;
  int buf_index, next_avc;
  uint8_t *ptr;

  if (!buf_size)
    return 0;

  buf_index     = 0;
  next_avc      = h->is_avc ? 0 : buf_size;
  for ( ; ; ) {
    int src_length, dst_length, consumed, nalsize = 0;

    if (buf_index >= next_avc) {
      nalsize = get_avc_nalsize(h, buf, buf_size, &buf_index);
      if (nalsize < 0)
        break;
      next_avc = buf_index + nalsize;
    } else {
      buf_index = find_start_code(buf, buf_size, buf_index, next_avc);
      if (buf_index >= buf_size)
        break;
      if (buf_index >= next_avc)
        continue;
    }
    src_length = next_avc - buf_index;

    ptr = h264_decode_nal(h, buf + buf_index, &dst_length,
        &consumed, src_length);
    if (!ptr || dst_length < 0)
      break;

    buf_index += consumed;

    init_get_bits(&h->gb, ptr, 8 * dst_length);
    if (h->nal_unit_type == 7) {
      if (!avctx->width || !avctx->height) {
        if (xmedia::h264_decode_sps(&h->gb, &h->sps) < 0) {
          LOGE("Parse sps failed");
          break;
        }

        avctx->width  = 16*h->sps.mb_width;
        avctx->height = 16*h->sps.mb_height*(2-h->sps.frame_mbs_only_flag);
      }
    }
  }
  return 0;
}

int find_start_code(const uint8_t *buf, int buf_size,
                    int buf_index, int next_avc)
{
  uint32_t state = -1;
  const uint8_t *p = buf + buf_index,
        *end = buf + next_avc + 1;
  int i;

  if (p >= end) {
    buf_index = end - buf - 1;
    goto found;
  }

  for (i = 0; i < 3; i++) {
    uint32_t tmp = state << 8;
    state = tmp + *(p++);
    if (tmp == 0x100 || p == end) {
      buf_index = p - buf - 1;
      goto found;
    }
  }

  while (p < end) {
    if      (p[-1] > 1      ) p += 3;
    else if (p[-2]          ) p += 2;
    else if (p[-3]|(p[-1]-1)) p++;
    else {
      p++;
      break;
    }
  }

  p = MIN(p, end) - 4;
  state = ntohl(* (uint32_t *) p);

  buf_index = p + 4 - buf - 1;

found:
  return MIN(buf_index, buf_size);
}

uint8_t *h264_decode_nal(H264Context *h, const uint8_t *src,
                         int *dst_length, int *consumed, int length)
{
  int i, si, di;
  uint8_t *dst;
  int bufidx;

  h->nal_unit_type = src[0] & 0x1F;

  src++;
  length--;

#define STARTCODE_TEST                                        \
  if (i + 2 < length && src[i + 1] == 0 && src[i + 2] <= 3) { \
    if (src[i + 2] != 3 && src[i + 2] != 0) {                 \
      /* startcode, so we must be past the end */             \
      length = i;                                             \
    }                                                         \
    break;                                                    \
  }

  for (i = 0; i + 1 < length; i += 2) {
    if (src[i])
      continue;
    if (i > 0 && src[i - 1] == 0)
      i--;
    STARTCODE_TEST;
  }

  // Use second escape buffer for inter data
  bufidx = h->nal_unit_type == 4 ? 1 : 0;

  uint32_t wanted_size = length + 256*1024 + INPUT_BUFFER_PADDING_SIZE;
  if (h->rbsp_buffer_size[bufidx] < wanted_size) {
    uint8_t *p = (uint8_t *) realloc(h->rbsp_buffer[bufidx],
                                     wanted_size);
    if (!p) {
      LOGE("realloc for rbsp_buffer[%d] failed: %s",
           bufidx, ERRNOMSG);
      return NULL;
    }
    memset(p, 0, wanted_size);
    h->rbsp_buffer[bufidx] = p;
    h->rbsp_buffer_size[bufidx] = wanted_size;
  }
  dst = h->rbsp_buffer[bufidx];

  if (i >= length - 1){ // No escaped 0
    *dst_length = length;
    *consumed = length + 1; //+1 for the header
    memcpy(dst, src, length);
    return dst;
  }

  memcpy(dst, src, i);
  si = di = i;
  while (si + 2 < length) {
    // remove escapes (very rare 1:2^22)
    if (src[si + 2] > 3) {
      dst[di++] = src[si++];
      dst[di++] = src[si++];
    } else if (src[si] == 0 && src[si + 1] == 0 && src[si + 2] != 0) {
      if (src[si + 2] == 3) { // escape
        dst[di++]  = 0;
        dst[di++]  = 0;
        si        += 3;
        continue;
      } else // next start code
        goto nsc;
    }

    dst[di++] = src[si++];
  }
  while (si < length)
    dst[di++] = src[si++];

nsc:
  memset(dst + di, 0, INPUT_BUFFER_PADDING_SIZE);

  *dst_length = di;
  *consumed   = si + 1; // +1 for the header
  /* FIXME store exact number of bits in the getbitcontext
   * (it is needed for decoding) */
  return dst;
}

int get_avc_nalsize(H264Context *h, const uint8_t *buf,
                    int buf_size, int *buf_index)
{
  int i, nalsize = 0;

  if (*buf_index >= buf_size - h->nal_length_size)
    return -1;

  for (i = 0; i < h->nal_length_size; i++)
    nalsize = ((unsigned)nalsize << 8) | buf[(*buf_index)++];
  if (nalsize <= 0 || nalsize > buf_size - *buf_index) {
    LOGE("AVC: nal size %d", nalsize);
    return -1;
  }
  return nalsize;
}

int av_compare_ts(int64_t ts_a, AVRational tb_a,
                  int64_t ts_b, AVRational tb_b)
{
  int64_t a = tb_a.num * (int64_t)tb_b.den;
  int64_t b = tb_b.num * (int64_t)tb_a.den;
  if ((abs(ts_a)|a|abs(ts_b)|b) <= INT_MAX)
    return (ts_a*a > ts_b*b) - (ts_a*a < ts_b*b);
  if (av_rescale_rnd(ts_a, a, b, AV_ROUND_DOWN) < ts_b)
    return -1;
  if (av_rescale_rnd(ts_b, b, a, AV_ROUND_DOWN) < ts_a)
    return 1;
  return 0;
}

void frac_init(AVFrac *f, int64_t val, int64_t num, int64_t den)
{
  num += (den >> 1);
  if (num >= den) {
    val += num / den;
    num  = num % den;
  }
  f->val = val;
  f->num = num;
  f->den = den;
}

void frac_add(AVFrac *f, int64_t incr)
{
  int64_t num, den;

  num = f->num + incr;
  den = f->den;
  if (num < 0) {
    f->val += num / den;
    num     = num % den;
    if (num < 0) {
      num += den;
      f->val--;
    }
  } else if (num >= den) {
    f->val += num / den;
    num     = num % den;
  }
  f->num = num;
}

void estimate_timings_from_pts(FormatContext *ic, off_t old_offset)
{
  Stream *st;
  unsigned i;

  // Flush packet queue
  flush_packet_queue(ic);

  for (i = 0; i < ic->nb_streams; ++i) {
    st = ic->streams[i];
    if (st->start_time == -1 &&
        st->codec->codec_type != MEDIA_TYPE_UNKNOWN)
      LOGW("start time for stream %d is not set in estimate_timings_from_pts", i);

    if (st->parser) {
      parser_close(st->parser);
      st->parser = NULL;
    }
  }

  update_stream_timings(ic);

  ic->file->seek_to(old_offset);
  for (i = 0; i < ic->nb_streams; ++i) {
    st = ic->streams[i];
    st->cur_dts = st->first_dts;
  }
}

void update_stream_timings(FormatContext *ic)
{
  int64_t start_time, start_time1;
  Stream *st;

  start_time = INT64_MAX;
  for (unsigned i = 0; i < ic->nb_streams; ++i) {
    st = ic->streams[i];
    if (st->start_time != -1 && st->time_base.den) {
      start_time1 = av_rescale_q(st->start_time, st->time_base,
                                 AV_TIME_BASE_Q);
      start_time = MIN(start_time, start_time1);
    }
  }

  if (start_time != INT64_MAX) {
    ic->start_time = start_time;
  }
}

void estimate_timings(FormatContext *ic, off_t old_offset)
{
  estimate_timings_from_pts(ic, old_offset);

  for (unsigned i = 0; i < ic->nb_streams; ++i) {
    Stream *st = ic->streams[i];
    UNUSED(st);
#ifdef DEBUG
    LOGD("%d: start_time: %lf", i,
         (double) st->start_time / AV_TIME_BASE);
#endif
  }
#ifdef DEBUG
  LOGD("stream: start_time: %lf",
       (double) ic->start_time / AV_TIME_BASE);
#endif
}

unsigned int choose_output(FormatContext *ic)
{
  int64_t opts_min = INT64_MAX;
  unsigned index = 0;

  for (unsigned i = 0; i < ic->nb_streams; ++i) {
    Stream *st = ic->streams[i];
    int opts = av_rescale_q(st->cur_dts, st->time_base,
                            AV_TIME_BASE_Q);
    if (opts < opts_min) {
      opts_min = opts;
      index = i;
    }
  }
  return index;
}

int interleave_add_packet(FormatContext *s, Packet *pkt,
                          int (*compare)(FormatContext *, Packet *, Packet *))
{
  PacketList **next_point, *this_pktl;
  Stream *st   = s->streams[pkt->stream_index];

  this_pktl = (PacketList *) calloc(1, sizeof(PacketList));
  if (!this_pktl) {
    LOGE("calloc for this_pktl failed: %s", ERRNOMSG);
    return -1;
  }
  dup_packet(&this_pktl->pkt, pkt);

  if (st->last_in_packet_buffer) {
    next_point = &(st->last_in_packet_buffer->next);
  } else {
    next_point = &s->packet_buffer;
  }

  if (*next_point) {
    if (compare(s, &s->packet_buffer_end->pkt, pkt)) {
      while (*next_point &&
             !compare(s, &(*next_point)->pkt, pkt))
        next_point = &(*next_point)->next;
      if (*next_point)
        goto next_non_null;
    } else {
      next_point = &(s->packet_buffer_end->next);
    }
  }

  assert(!*next_point);

  s->packet_buffer_end = this_pktl;
next_non_null:

  this_pktl->next = *next_point;

  st->last_in_packet_buffer =
                *next_point = this_pktl;

  return 0;
}

int interleave_compare_dts(FormatContext *s, Packet *next,
                           Packet *pkt)
{
  Stream *st  = s->streams[pkt->stream_index];
  Stream *st2 = s->streams[next->stream_index];
  int comp    = av_compare_ts(next->dts, st2->time_base, pkt->dts,
                              st->time_base);

  if (comp == 0)
    return pkt->stream_index < next->stream_index;
  return comp > 0;
}

int read_packet(FormatContext *s, Packet *pkt)
{
  SAFE_FREE(pkt->data);
  return s->iformat->read_packet(s, pkt);
}

int read_frame_internal(FormatContext *s, Packet *pkt)
{
  int ret = 0, got_packet = 0;
  unsigned i;

  bzero(pkt, sizeof(*pkt));

  while (!got_packet && !s->parse_queue) {
    Stream *st;

    ret = read_packet(s, pkt);
    if (ret < 0) {
      // Flush the parsers
      for (i = 0; i < s->nb_streams; ++i) {
        st = s->streams[i];
        if (st->parser && st->need_parsing)
          parse_packet(s, NULL, st->index);
      }
      /* All remaining packets are now in parse_queue =>
       * really terminate parsing */
      break;
    }
    Packet cur_pkt = *pkt;
    st = s->streams[cur_pkt.stream_index];

    if (cur_pkt.pts != -1 &&
        cur_pkt.dts != -1 &&
        cur_pkt.pts < cur_pkt.dts) {
      LOGW("Invalid timestamps stream=%d, pts=%lld, dts=%lld, size=%d",
           cur_pkt.stream_index, cur_pkt.pts, cur_pkt.dts, cur_pkt.size);
    }
#ifdef XDEBUG
    LOGD("read_packet stream=%d, pts=%lld, dts=%lld, size=%d, duration=%d",
         cur_pkt.stream_index,
         cur_pkt.pts,
         cur_pkt.dts,
         cur_pkt.size,
         cur_pkt.duration);
#endif

    if (st->need_parsing) {
      if (!st->parser) {
        st->parser = parser_init(st->codec->codec_id);
        if (!st->parser) {
          LOGE("Parser not found for codec(codec_id:%d)",
               st->codec->codec_id);
          return -1;
        }
      }

      if ((ret = parse_packet(s, &cur_pkt, cur_pkt.stream_index)) < 0)
        return ret;
    }

    if (!st->need_parsing || !st->parser) {
      // No parser needed: we just output the packet as is
      *pkt = cur_pkt;
      compute_pkt_fields(s, st, NULL, pkt);
      got_packet = 1;
    }
  }

  if (!got_packet && s->parse_queue)
    ret = read_from_packet_buffer(&s->parse_queue, &s->parse_queue_end, pkt);

#ifdef XDEBUG
  LOGD("read_frame_internal stream=%d, pts=%lld, dts=%lld, "
       "size=%d, duration=%d",
       pkt->stream_index, pkt->pts, pkt->dts,
       pkt->size, pkt->duration);
#endif
  return ret;
}

int format_find_stream_info(FormatContext *ic)
{
  unsigned i;
  int count, ret = 0;
  off_t old_offset = ic->file->cursor();
  int64_t read_size;
  int64_t probesize = 5000000;
  Stream *st;
  Packet *pkt, pkt1;

#ifdef XDEBUG
  LOGD("Before format_find_stream_info() pos: %lld",
       old_offset);
#endif

  for (i = 0; i < ic->nb_streams; ++i) {
    st = ic->streams[i];

    if (st->codec->codec_type == MEDIA_TYPE_VIDEO) {
      if (!st->codec->time_base.num)
        st->codec->time_base = st->time_base;
    }
    // Only for the split stuff
    if (!st->parser) {
      st->parser = parser_init(st->codec->codec_id);
      if (!st->parser && st->need_parsing) {
        LOGE("Parser not found for codec(codec_id:%d)",
             st->codec->codec_id);
      }
    }

    // It's NOT possible to get paramters just by opening the decoder,
    // we need further process
  }

  count = 0;
  read_size = 0;
  for ( ; ; ) {
    if (*ic->watch_variable) {
      ret = -1;
      break;
    }

    for (i = 0; i < ic->nb_streams; ++i) {
      st = ic->streams[i];
      if (!has_codec_parameters(st))
        break;
    }
    if (i == ic->nb_streams) {
      ret = count;
#ifdef XDEBUG
      LOGD("All info found");
#endif
      break;
    }

    if (read_size >= probesize) {
      ret = count;
      LOGE("Probe buffer size limit of %lld bytes reached", probesize);
      break;
    }

    ret = read_frame_internal(ic, &pkt1);
    if (ret < 0) {
      // EOF or error
      break;
    }

    if (read_size >= probesize) {
      LOGW("Probe buffer size limit of %lld bytes reached",
           probesize);
      break;
    }

    pkt = add_to_pktbuf(&ic->packet_buffer, &pkt1,
                        &ic->packet_buffer_end);
    if (!pkt) {
      ret = -1;
      goto out;
    }

    // NOTE: No need to decode the frame, we only parse it

    read_size += pkt->size;
    SAFE_FREE(pkt1.data);
    ++count;
  }

  if (probesize)
    estimate_timings(ic, old_offset);

  if (ret >= 0 && ic->nb_streams) {
    // We could not have all the codec parameters before EOF
    ret = -1;
  }
  for (i = 0; i < ic->nb_streams; ++i) {
    st = ic->streams[i];
    if (!has_codec_parameters(st)) {
      LOGW("Could not find codec parameters for stream %d", i);
    } else {
      ret = 0;
    }
  }

out:
#ifdef XDEBUG
  LOGD("After format_find_stream_info() pos: %lld",
       ic->file->cursor());
#endif
  return ret;
}

int process_input(FormatContext *ic, int stream_index)
{
  Stream *st = ic->streams[stream_index];
  int ret;
  Packet pkt;

  ret = read_frame_internal(ic, &pkt);
  if (ret < 0)
    return -1;

#ifdef XDEBUG
  LOGI("demuxer -> stream: %d pkt_pts:%lld, pkt_dts:%lld size:%d duration:%d pos:%lld",
       pkt.stream_index, pkt.pts, pkt.dts, pkt.size, pkt.duration, pkt.pos);
#endif

  if (pkt.dts != -1)
    pkt.dts += av_rescale_q(ic->ts_offset, AV_TIME_BASE_Q, st->time_base);
  if (pkt.pts != -1)
    pkt.pts += av_rescale_q(ic->ts_offset, AV_TIME_BASE_Q, st->time_base);

#ifdef XDEBUG
  LOGI("demuxer+ffmpeg -> stream: %d pkt_pts:%lld, pkt_dts:%lld size:%d duration:%d pos:%lld",
       pkt.stream_index, pkt.pts, pkt.dts, pkt.size, pkt.duration, pkt.pos);
#endif

  do_streamcopy(ic, &pkt);

  return 0;
}

void do_streamcopy(FormatContext *ic, Packet *pkt)
{
  Stream *st = ic->streams[pkt->stream_index];
  Packet opkt = *pkt;

  if (pkt->pts != -1)
    opkt.pts = av_rescale_q(pkt->pts, st->time_base, ic->otime_base);
  if (pkt->dts != -1)
    opkt.dts = av_rescale_q(pkt->dts, st->time_base, ic->otime_base);

  opkt.duration = av_rescale_q(pkt->duration, st->time_base, ic->otime_base);
  *pkt = opkt;

  write_frame(ic, pkt);
}

void write_frame(FormatContext *ic, Packet *pkt)
{
  Stream *st = ic->streams[pkt->stream_index];
  int ret = 0;

  if (st->codec->codec_type == MEDIA_TYPE_AUDIO) {
    // Remove the first 7 bytes of adts header
    // NOTE: No need to remove for we need info in adts header
    //memmove(pkt->data, pkt->data + AAC_ADTS_HEADER_SIZE,
    //        (pkt->size -= AAC_ADTS_HEADER_SIZE));
  }

#ifdef XDEBUG
  LOGI("muxer <- stream: %d pkt_pts:%lld pkt_dts:%lld size:%d duration:%d pos:%lld",
       pkt->stream_index, pkt->pts, pkt->dts, pkt->size, pkt->duration, pkt->pos);
#endif

  ret = interleaved_write_frame(ic, pkt);
  if (ret < 0) {
    LOGE("interleaved_write_frame() failed");
  }

  SAFE_FREE(pkt->data);
}

int interleaved_write_frame(FormatContext *ic, Packet *pkt)
{
  int ret = 0, flush = 0;

  if (pkt->stream_index < 0 ||
      pkt->stream_index >= (int) ic->nb_streams) {
    LOGE("Invalid packet stream index: %d",
         pkt->stream_index);
    return -1;
  }

  if (!pkt) {
#ifdef XDEBUG
    LOGI("interleaved_write_frame() FLUSH");
#endif
    flush = 1;
    *ic->watch_variable = true;
  }

  while (!*ic->watch_variable) {
    Packet opkt;
    int ret = interleave_packet_per_dts(ic, &opkt, pkt, flush);
    if (pkt) {
      SAFE_FREE(pkt->data);
      pkt = NULL;
    }
    if (ret <= 0) {
      return ret;
    }

#ifdef XDEBUG
    LOGI("opkt.stream_index=%d, opkt.pts=%lld",
         opkt.stream_index, opkt.pts);
#endif
    if (ic->cb) {
      MediaType mt = ic->streams[opkt.stream_index]->codec->codec_type;
      int is_video = mt == MEDIA_TYPE_VIDEO ? 1 : 0;

      Frame frame;
      if (frame.make_frame(opkt.dts, opkt.data, opkt.size, true, opkt.pts - opkt.dts) < 0 ||
          (ret = ic->cb(ic->opaque, &frame, is_video)) < 0) {
        *ic->watch_variable = true;
        ret = -1;
      }
      if (ret >= 0)
        ++ic->streams[opkt.stream_index]->nb_frames;

      frame.clear();
    } else {
      SAFE_FREE(opkt.data);
    }
  }

  return ret;
}

int interleave_packet_per_dts(FormatContext *s, Packet *out,
                              Packet *pkt, int flush)
{
  PacketList *pktl;
  unsigned stream_count = 0;
  unsigned noninterleaved_count = 0;
  int ret;
  unsigned i;

  if (pkt) {
    if ((ret = interleave_add_packet(s, pkt, interleave_compare_dts)) < 0)
      return ret;
  }

  for (i = 0; i < s->nb_streams; i++) {
    if (s->streams[i]->last_in_packet_buffer) {
      ++stream_count;
    } else {
      ++noninterleaved_count;
    }
  }

  if (s->nb_streams == stream_count)
    flush = 1;

  if (s->max_interleave_delta > 0 &&
      s->packet_buffer &&
      !flush &&
      s->nb_streams == stream_count+noninterleaved_count) {
    Packet *top_pkt = &s->packet_buffer->pkt;
    int64_t delta_dts = INT64_MIN;
    int64_t top_dts = av_rescale_q(top_pkt->dts,
                                   s->streams[top_pkt->stream_index]->time_base,
                                   AV_TIME_BASE_Q);

    for (i = 0; i < s->nb_streams; i++) {
      int64_t last_dts;
      const PacketList *last = s->streams[i]->last_in_packet_buffer;

      if (!last)
        continue;

      last_dts = av_rescale_q(last->pkt.dts,
                              s->streams[i]->time_base,
                              AV_TIME_BASE_Q);
      delta_dts = MAX(delta_dts, last_dts - top_dts);
    }

    if (delta_dts > s->max_interleave_delta) {
      LOGE("Delay between the first packet and last packet in the "
           "muxing queue is %lld > %lld: forcing output",
           delta_dts, s->max_interleave_delta);
      flush = 1;
    }
  }

  if (stream_count && flush) {
    Stream *st;
    pktl = s->packet_buffer;
    *out = pktl->pkt;
    st   = s->streams[out->stream_index];

    s->packet_buffer = pktl->next;
    if (!s->packet_buffer)
      s->packet_buffer_end = NULL;

    if (st->last_in_packet_buffer == pktl)
      st->last_in_packet_buffer = NULL;
    SAFE_FREE(pktl);

    return 1;
  } else {
    bzero(out, sizeof(*out));
    return 0;
  }
}

int write_trailer(FormatContext *s)
{
  int ret;

  for ( ; ; ) {
    Packet opkt;
    ret = interleave_packet_per_dts(s, &opkt, NULL, 1);
    if (ret < 0)
      return -1;
    if (!ret)
      break;

#ifdef XDEBUG
    LOGI("opkt.stream_index=%d, opkt.pts=%lld",
         opkt.stream_index, opkt.pts);
#endif

    if (s->cb) {
      MediaType mt = s->streams[opkt.stream_index]->codec->codec_type;
      int is_video = mt == MEDIA_TYPE_VIDEO ? 1 : 0;

      Frame frame;
      if (frame.make_frame(opkt.pts, opkt.data, opkt.size, true) < 0 ||
          s->cb(s->opaque, &frame, is_video) < 0) {
        *s->watch_variable = true;
        ret = -1;
      }
      if (ret >= 0)
        ++s->streams[opkt.stream_index]->nb_frames;

      frame.clear();
    } else {
      SAFE_FREE(opkt.data);
    }
  }
  return ret;
}

int check_h264_startcode(const Packet *pkt)
{
  if (pkt->size < 5 || ENTOHL(*(uint32_t*)pkt->data) != 0x00000001)
    return -1;
  return 0;
}

const uint8_t *priv_find_start_code(const uint8_t *p, const uint8_t *end,
                                    uint32_t *state)
{       
  int i; 

  if (p >= end)
    return end;

  for (i = 0; i < 3; i++) { 
    uint32_t tmp = *state << 8;
    *state = tmp + *(p++);
    if (tmp == 0x100 || p == end)
      return p;
  }       

  while (p < end) { 
    if      (p[-1] > 1      ) p += 3;
    else if (p[-2]          ) p += 2;
    else if (p[-3]|(p[-1]-1)) p++;
    else {
      p++;
      break;
    }
  }

  p = MIN(p, end) - 4;
  *state = ENTOHL(*(uint32_t *)p);

  return p + 4;
}

}
