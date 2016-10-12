#ifndef _FFMPEG_H_
#define _FFMPEG_H_

#include <xfile.h>
#include <get_bits.h>
#include <xmedia.h>

#include "xtype.h"

#define AV_TIME_BASE        1000000
#define AV_TIME_BASE_Q      (AVRational){1, AV_TIME_BASE}

#define END_NOT_FOUND (-100)

#define INPUT_BUFFER_PADDING_SIZE   32

#define PARSER_PTS_NB 4
#define PARSER_FLAG_FETCHED_OFFSET 0x0004

#define RAW_PACKET_BUFFER_SIZE 2500000

#define AV_PKT_FLAG_KEY     0x0001 // The packet contains a keyframe
#define AV_PKT_FLAG_CORRUPT 0x0002 // The packet content is corrupted

using namespace xutil;
using namespace xmedia;

namespace ffmpeg {

struct Packet {
  uint8_t *data;
  int size;
  int64_t pts, dts;
  int64_t pos;
  int stream_index;
  int duration;

  Packet() { memset(this, 0, sizeof(*this)); }
  int clone(Packet *pkt, bool reuse_buffer);
};

struct PacketList {
  Packet pkt;
  PacketList *next;
};

enum MediaType {
  MEDIA_TYPE_UNKNOWN,
  MEDIA_TYPE_VIDEO,
  MEDIA_TYPE_AUDIO,
};

enum CodecID {
  CODEC_ID_NONE,
  CODEC_ID_H264,
  CODEC_ID_AAC
};

struct AVRational {
  int num;
  int den;
};

struct Codec {
  const char *name;
  MediaType type;
  CodecID id;
};

struct CodecContext {
  enum MediaType codec_type;
  enum CodecID codec_id;
  Codec *codec;

  // Video only
  int width, height;

  int frame_size;

  // Audio only
  int sample_rate;
  int channels;

  AVRational time_base;
  int bit_rate;
};

struct CodecParser;
struct CodecParserContext {
  void *priv_data;
  CodecParser *parser;
  int64_t pts, dts;
  int64_t pos;
  int key_frame;

  int flags;

  int64_t last_pts;               
  int64_t last_dts;
  int fetch_timestamp;

  int cur_frame_start_index;
  int64_t cur_frame_offset[PARSER_PTS_NB];
  int64_t cur_frame_pts[PARSER_PTS_NB];
  int64_t cur_frame_dts[PARSER_PTS_NB];

  int64_t offset;      ///< byte offset from starting packet start
  int64_t cur_frame_end[PARSER_PTS_NB];

  int64_t cur_offset; /* current offset
                         (incremented by each av_parser_parse()) */
  int64_t next_frame_offset; /* offset of the next frame */

  int64_t cur_frame_pos[PARSER_PTS_NB];

  int64_t last_pos;

  int64_t frame_offset;
};

struct CodecParser {
  CodecID codec_id;
  int priv_data_size;
  int (*parser_init)(CodecParserContext *s);
  int (*parser_parse)(CodecParserContext *s,
                      CodecContext *avctx,
                      const uint8_t **poutbuf, int *poutbuf_size,
                      const uint8_t *buf, int buf_size);
  void (*parser_close)(CodecParserContext *s);
  int (*split)(CodecContext *avctx, const uint8_t *buf, int buf_size);
};

struct ParseContext {
  uint8_t *buffer;
  int index;
  int last_index;
  unsigned int buffer_size;
  uint32_t state;             ///< contains the last few bytes in MSB order
  //int frame_start_found;
  int overread;               ///< the number of bytes which where irreversibly read from the next frame
  int overread_index;         ///< the index into ParseContext.buffer of the overread bytes
  uint64_t state64;
};

struct Stream {
  int index;
  int id;
  CodecContext *codec;
  int64_t start_time;
  int pts_wrap_bits;
  AVRational time_base;
  int need_parsing;
  CodecParserContext *parser;
  int64_t first_dts;
  int64_t cur_dts;
  PacketList *last_in_packet_buffer;
  int nb_index_entries;
  void *priv_data;
  int64_t nb_frames;
};

struct FormatContext;
struct InputFormat {
  const char *name;
  int priv_data_size;
  int (*read_packet)(FormatContext *, Packet *pkt);
};
struct OutputFormat {
  const char *name;
  int priv_data_size;
  int (*write_packet)(FormatContext *, Packet *pkt);
};

struct FormatContext {
  InputFormat *iformat;
  OutputFormat *oformat;
  xfile::File *file;
  unsigned int nb_streams;
  Stream **streams;
  int64_t start_time;
  PacketList *packet_buffer;
  PacketList *packet_buffer_end;
  PacketList *parse_queue;
  PacketList *parse_queue_end;
  int max_interleave_delta;
  void *priv_data;
  volatile bool *watch_variable;
  int64_t ts_offset;
  AVRational otime_base;
  int max_delay;
  FrameCb cb;
  void *opaque;
};

enum AVRounding {
  AV_ROUND_ZERO     = 0, ///< Round toward zero.
  AV_ROUND_INF      = 1, ///< Round away from zero.
  AV_ROUND_DOWN     = 2, ///< Round toward -infinity.
  AV_ROUND_UP       = 3, ///< Round toward +infinity.
  AV_ROUND_NEAR_INF = 5, ///< Round to nearest and halfway cases away from zero.
  AV_ROUND_PASS_MINMAX = 8192, ///< Flag to pass INT64_MIN/MAX through instead of rescaling, this avoids special cases for AV_NOPTS_VALUE
};

struct AACParseContext {
  ParseContext pc;
  int frame_size;
  int header_size;
  int (*sync) (uint64_t state, struct AACParseContext *hdr_info,
               int *need_next_header, int *new_frame_start);
  int channels;
  int sample_rate;
  int bit_rate;
  int samples;
  uint64_t channel_layout;

  int remaining_size;
  uint64_t state;

  int need_next_header;
  CodecID codec_id;
};

struct AACADTSHeaderInfo {
  uint32_t sample_rate;
  uint32_t samples;
  uint32_t bit_rate;    
  uint8_t  crc_absent;  
  uint8_t  object_type; 
  uint8_t  sampling_index;
  uint8_t  chan_config;
  uint8_t  num_aac_frames;
};

struct H264Context {
  CodecContext *avctx;
  int width, height;
  int got_first;
  int is_avc;
  int nal_unit_type;
  uint8_t *rbsp_buffer[2];
  unsigned int rbsp_buffer_size[2];
  int nal_length_size;
  GetBitContext gb;
  SPS sps;
};

struct AVFrac {
  int64_t val, num, den;
};

AVRational av_mul_q(AVRational b, AVRational c);
int av_reduce(int *dst_num, int *dst_den, int64_t num, int64_t den, int64_t max);
int64_t av_gcd(int64_t a, int64_t b);
int64_t av_rescale(int64_t a, int64_t b, int64_t c);
int64_t av_rescale_rnd(int64_t a, int64_t b, int64_t c, enum AVRounding rnd);
int64_t av_add_stable(AVRational ts_tb, int64_t ts, AVRational inc_tb, int64_t inc);
int64_t av_rescale_q(int64_t a, AVRational bq, AVRational cq);
int64_t av_rescale_q_rnd(int64_t a, AVRational bq, AVRational cq, enum AVRounding rnd);

void compute_frame_duration(FormatContext *s, int *pnum,
                            int *pden, Stream *st, CodecParserContext *pc, Packet *pkt);

Stream *format_new_stream(FormatContext *s);

void priv_set_pts_info(Stream *s, int pts_wrap_bits,
                       unsigned int pts_num, unsigned int pts_den);

int has_codec_parameters(Stream *st);

Packet *add_to_pktbuf(PacketList **packet_buffer, Packet *pkt,
                      PacketList **plast_pktl);
int read_from_packet_buffer(PacketList **pkt_buffer,
                            PacketList **pkt_buffer_end,
                            Packet      *pkt);
void flush_packet_queue(FormatContext *s);
void free_packet_buffer(PacketList **pkt_buf, PacketList **pkt_buf_end);

int dup_packet(Packet *dst, Packet *src);

CodecParserContext *parser_init(int codec_id);
void parser_close(CodecParserContext *s);

int parse_packet(FormatContext *s, Packet *pkt, int stream_index);
int parser_parse2(CodecParserContext *s, CodecContext *avctx,
                  uint8_t **poutbuf, int *poutbuf_size,
                  const uint8_t *buf, int buf_size,
                  int64_t pts, int64_t dts, int64_t pos);

void compute_pkt_fields(FormatContext *s, Stream *st,
                        CodecParserContext *pc, Packet *pkt);

void fetch_timestamp(CodecParserContext *s, int off, int remove);

int aac_parse_init(CodecParserContext *s1);
int aac_parse(CodecParserContext *s1,
              CodecContext *avctx,
              const uint8_t **poutbuf, int *poutbuf_size,
              const uint8_t *buf, int buf_size);
int aac_sync(uint64_t state, AACParseContext *hdr_info,
             int *need_next_header, int *new_frame_start);
void aac_parse_close(CodecParserContext *s);

int h264_parse_init(CodecParserContext *s);
int h264_parse(CodecParserContext *s,
               CodecContext *avctx,
               const uint8_t **poutbuf, int *poutbuf_size,
               const uint8_t *buf, int buf_size);
void h264_parse_close(CodecParserContext *s);

int combine_frame(ParseContext *pc, int next,
                  const uint8_t **buf, int *buf_size);

int priv_aac_parse_header(GetBitContext *gbc, AACADTSHeaderInfo *hdr);

int parse_nal_units(CodecParserContext *s,
                    CodecContext *avctx,
                    const uint8_t * const buf, int buf_size);

int get_avc_nalsize(H264Context *h, const uint8_t *buf,
                    int buf_size, int *buf_index);
int find_start_code(const uint8_t *buf, int buf_size,
                    int buf_index, int next_avc);
uint8_t *h264_decode_nal(H264Context *h, const uint8_t *src,
                         int *dst_length, int *consumed, int length);

int av_compare_ts(int64_t ts_a, AVRational tb_a,
                  int64_t ts_b, AVRational tb_b);

void frac_init(AVFrac *f, int64_t val, int64_t num, int64_t den);
void frac_add(AVFrac *f, int64_t incr);

void estimate_timings_from_pts(FormatContext *ic, off_t old_offset);
void update_stream_timings(FormatContext *ic);
void estimate_timings(FormatContext *ic, off_t old_offset);

unsigned int choose_output(FormatContext *ic);
int interleave_add_packet(FormatContext *s, Packet *pkt,
                          int (*compare)(FormatContext *, Packet *, Packet *));
int interleave_compare_dts(FormatContext *s, Packet *next,
                           Packet *pkt);

int read_packet(FormatContext *s, Packet *pkt);
int read_frame_internal(FormatContext *s, Packet *pkt);

int format_find_stream_info(FormatContext *ic);

int process_input(FormatContext *ic, int stream_index);
void do_streamcopy(FormatContext *ic, Packet *pkt);
void write_frame(FormatContext *ic, Packet *pkt);
int interleaved_write_frame(FormatContext *ic, Packet *pkt);
int interleave_packet_per_dts(FormatContext *ic, Packet *out,
                              Packet *pkt, int flush);
int write_trailer(FormatContext *s);

int check_h264_startcode(const Packet *pkt);
const uint8_t *priv_find_start_code(const uint8_t *p, const uint8_t *end,
                                    uint32_t *state);

}

#endif /* end of _FFMPEG_H_ */
