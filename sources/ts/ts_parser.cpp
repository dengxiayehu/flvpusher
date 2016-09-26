#include <cstdlib>
#include <xlog.h>

#include "ts_parser.h"
#include "ts_pusher.h"

//#define XDEBUG

namespace flvpusher {

static inline int get8(const uint8_t **pp, const uint8_t *p_end)
{
  const uint8_t *p;
  int c;

  p = *pp;
  if (p >= p_end)
    return -1;
  c   = *p++;
  *pp = p;
  return c;
}

static inline int get16(const uint8_t **pp, const uint8_t *p_end)
{
  const uint8_t *p;
  int c;

  p = *pp;
  if ((p + 1) >= p_end)
    return -1;
  c   = ntohs(* (uint16_t *) p);
  p  += 2;
  *pp = p;
  return c;
}

// Read and allocate a DVB string preceded by its length
static char *getstr8(const uint8_t **pp, const uint8_t *p_end)
{           
  int len;
  const uint8_t *p;
  char *str;

  p   = *pp;
  len = get8(&p, p_end);
  if (len < 0)
    return NULL;
  if ((p + len) > p_end)
    return NULL;
  str = (char *) malloc(len + 1);
  if (!str)
    return NULL;
  memcpy(str, p, len);
  str[len] = '\0';
  p  += len;
  *pp = p;
  return str;
}

/////////////////////////////////////////////////////////////

static uint32_t crc32table[256] = {   
  0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b,
  0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
  0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd, 0x4c11db70, 0x48d0c6c7,
  0x4593e01e, 0x4152fda9, 0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
  0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3,
  0x709f7b7a, 0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
  0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5, 0xbe2b5b58, 0xbaea46ef,
  0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
  0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb,
  0xceb42022, 0xca753d95, 0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
  0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077, 0x30476dc0,
  0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
  0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16, 0x018aeb13, 0x054bf6a4,
  0x0808d07d, 0x0cc9cdca, 0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
  0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08,
  0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
  0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b, 0xbb60adfc,
  0xb6238b25, 0xb2e29692, 0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
  0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a, 0xe0b41de7, 0xe4750050,
  0xe9362689, 0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
  0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34,
  0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
  0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb, 0x4f040d56, 0x4bc510e1,
  0x46863638, 0x42472b8f, 0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
  0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5,
  0x3f9b762c, 0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
  0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623, 0xf12f560e, 0xf5ee4bb9,
  0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
  0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd,
  0xcda1f604, 0xc960ebb3, 0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
  0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6, 0x9ff77d71,
  0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
  0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640, 0x4e8ee645, 0x4a4ffbf2,
  0x470cdd2b, 0x43cdc09c, 0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
  0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e,
  0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
  0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d, 0x2056cd3a,
  0x2d15ebe3, 0x29d4f654, 0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
  0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c, 0xe3a1cbc1, 0xe760d676,
  0xea23f0af, 0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
  0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662,
  0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
  0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

static uint32_t crc32(const uint8_t *data, int len)
{
  int i;
  uint32_t crc = 0xffffffff;
  for (i = 0; i < len; ++i) {
    crc = (crc << 8) ^ crc32table[((crc >> 24) ^ *data++) & 0xff];
  }
  return crc;
}

/////////////////////////////////////////////////////////////

TSParser::TSParser() :
  m_ts(NULL)
{
}

TSParser::~TSParser()
{
  m_file.close();
  ts_free(m_ts);
}

int TSParser::set_file(const std::string &ts_file, bool hls_segment)
{
  if (!m_file.open(ts_file, "rb"))
    return -1;

  if (init() < 0) {
    LOGE("TSParser's init() failed");
    return -1;
  }

  if (format_find_stream_info(m_ts->stream) < 0)
    return -1;

  if (!hls_segment) {
    int64_t timestamps = 0;
    FormatContext *ic = m_ts->stream;
    if (ic->start_time != -1)
      timestamps += ic->start_time;
    ic->ts_offset = 0 - timestamps;
  }
  return 0;
}

bool TSParser::eof() const
{
  return m_file.is_opened() ?
    m_file.eof() || m_file.cursor() >= m_file.size() : true;
}

int TSParser::get_resolution(uint32_t &width, uint32_t &height)
{
  if (!m_ts) {
    LOGE("TSParser not initialized, call set_file() first");
    return -1;
  }

  FormatContext *ic = m_ts->stream;
  for (unsigned i = 0; i < ic->nb_streams; ++i) {
    Stream *st = ic->streams[i];
    if (st->codec->codec_type == MEDIA_TYPE_VIDEO) {
      if (st->codec->width && st->codec->height) {
        width = st->codec->width;
        height = st->codec->height;
        return 0;
      }
    }
  }

  return -1;
}

int TSParser::init()
{
  // Read the first 8192 bytes to get packet size
  off_t pos = m_file.cursor();

  if (ts_init(m_ts, &m_file) < 0)
    return -1;

  // First do a scan to get all the services
  m_file.seek_to(pos);

  ts_open_section_filter(m_ts, SDT_PID, sdt_cb, m_ts, 1);

  ts_open_section_filter(m_ts, PAT_PID, pat_cb, m_ts, 1);

  // Hope packets# are enough to figure out the services
  handle_packets(m_ts, 5000000 / m_ts->raw_packet_size);

  // Back to where we were
  return m_file.seek_to(pos) ? 0 : -1;
}

int TSParser::ts_init(TSContext *&ts, xfile::File *file)
{
  FormatContext *ic = (FormatContext *) calloc(1, sizeof(FormatContext));
  if (!ic) {
    LOGE("calloc for FormatContext failed: %s",
        ERRNOMSG);
    return -1;
  }
  ic->watch_variable = interrupt_variable();
  ic->start_time = -1;
  ic->file = file;
  ic->max_interleave_delta = 10000000;
  ic->otime_base = (AVRational) {1, 1000};
  ic->iformat = &mpegts_demuxer;
  if (ic->iformat->priv_data_size > 0) {
    ic->priv_data = calloc(1, ic->iformat->priv_data_size);;
    if (!ic->priv_data) {
      LOGE("calloc for ic->iformat->priv_data failed: %s",
           ERRNOMSG);
      return -1;
    }
  }

  ts = (TSContext *) ic->priv_data;
  ts->stream = ic;

  uint8_t buf[8*1024] = {0};
  if (!file->read_buffer(buf, sizeof(buf))) {
    if (sizeof(buf) > (size_t) file->size()) {
      LOGE("Too small the ts file is (size: %ld)",
           (long) file->size());
    }
    return -1;
  }
  ts->raw_packet_size = get_packet_size(buf, sizeof(buf));
  if (ts->raw_packet_size <= 0) {
    LOGE("Could not detect TS packet size (%d)",
         ts->raw_packet_size);
    return -1;
  }
  return 0;
}

int TSParser::process(void *opaque, FrameCb cb)
{
  FormatContext *ic = m_ts->stream;
  unsigned i;
  int ret;

  ic->cb      = cb;
  ic->opaque  = opaque;

  while (!*ic->watch_variable) {
    i = choose_output(ic);

    ret = process_input(ic, i);
    if (ret < 0) break;
  }

  write_trailer(ic);
  return 0;
}

int TSParser::analyze(const uint8_t *buf, int size,
    int packet_size, int *index)
{
  int stat[TS_MAX_PACKET_SIZE];
  int stat_all = 0;
  int i;
  int best_score = 0;

  memset(stat, 0, packet_size * sizeof(*stat));

  for (i = 0; i < size - 3; i++) {
    if (buf[i] == 0x47 && !(buf[i + 1] & 0x80) && buf[i + 3] != 0x47) {
      int x = i % packet_size;
      stat[x]++;
      stat_all++;
      if (stat[x] > best_score) {
        best_score = stat[x];
        if (index)
          *index = x;
      }
    }
  }

  return best_score - MAX(stat_all - 10*best_score, 0)/10;
}

int TSParser::get_packet_size(const uint8_t *buf, int size)
{
  if (size < (TS_FEC_PACKET_SIZE * 5 + 1))
    return -1;

  int score, fec_score, dvhs_score;
  score      = analyze(buf, size, TS_PACKET_SIZE, NULL);
  dvhs_score = analyze(buf, size, TS_DVHS_PACKET_SIZE, NULL);
  fec_score  = analyze(buf, size, TS_FEC_PACKET_SIZE, NULL);
#ifdef XDEBUG
  LOGD("score: %d, dvhs_score: %d, fec_score: %d",
       score, dvhs_score, fec_score);
#endif

  if (score > fec_score && score > dvhs_score)
    return TS_PACKET_SIZE;
  else if (dvhs_score > score && dvhs_score > fec_score)
    return TS_DVHS_PACKET_SIZE;
  else if (score < fec_score && dvhs_score < fec_score)
    return TS_FEC_PACKET_SIZE;
  else
    return -1;
}

TSParser::TSFilter *TSParser::ts_open_filter(TSContext *ts, unsigned int pid,
                                             TSFilterType type)
{
  TSFilter *filter;

#ifdef XDEBUG
  LOGD("Filter: pid=0x%x", pid);
#endif

  if (pid >= NB_PID_MAX || ts->pids[pid]) {
    LOGE("pid(0x%x) too large or filter already attached",
         pid);
    return NULL;
  }
  filter = (TSFilter *) calloc(1, sizeof(*filter));
  if (!filter) {
    LOGE("calloc for filter(pid=0x%x) failed: %s",
         pid, ERRNOMSG);
    return NULL;
  }
  // Record it
  ts->pids[pid] = filter;

  filter->type    = type;
  filter->pid     = pid;
  filter->last_cc = -1;
  filter->last_pcr= -1;
  return filter;
}

TSParser::TSFilter *TSParser::ts_open_section_filter(TSContext *ts,
                                                     unsigned int pid,
                                                     SectionCallback *section_cb,
                                                     void *opaque,
                                                     int check_crc)
{
  TSFilter *filter;
  TSSectionFilter *sec;

  if (!(filter = ts_open_filter(ts, pid, TS_SECTION)))
    return NULL;
  sec = &filter->u.section_filter;
  sec->section_cb = section_cb;
  sec->opaque     = opaque;
  // Alloc enough space for a complete PSI
  sec->section_buf= (uint8_t *) malloc(MAX_SECTION_SIZE);
  sec->check_crc  = check_crc;
  if (!sec->section_buf) {
    LOGE("malloc for section_buf(pid=0x%x) failed: %s",
         pid, ERRNOMSG);
    SAFE_FREE(filter);
    return NULL;
  }
  return filter;
}

void TSParser::pat_cb(TSFilter *filter,
                      const uint8_t *section, int section_len)
{
  TSContext *ts = (TSContext *) filter->u.section_filter.opaque;
  SectionHeader h1, *h = &h1; // A way to use pointer instead of obj
  const uint8_t *p, *p_end;
  int sid, pmt_pid;

  p_end = section + section_len - 4 /* crc length */;
  p     = section;
  if (parse_section_header(h, &p, p_end) < 0)
    return;
  if (h->tid != PAT_TID) // Not pat actually 
    return;

  clear_programs(ts);
  for ( ; ; ) {
    sid = get16(&p, p_end);
    if (sid < 0)
      break;
    pmt_pid = get16(&p, p_end);
    if (pmt_pid < 0)
      break;
    pmt_pid &= 0x1fff;

    // Wrong pmt_pid found, duplicated
    if (pmt_pid == ts->current_pid)
      break;

#ifdef XDEBUG
    LOGD("PAT: sid=0x%x pid=0x%x", sid, pmt_pid);
#endif

    if (sid == 0x0000) {
      // NIT info
    } else {
      TSFilter *fil = ts->pids[pmt_pid];
      if (fil) {
        if (fil->type != TS_SECTION ||
            fil->pid != pmt_pid ||
            fil->u.section_filter.section_cb != pmt_cb) {
          ts_close_filter(ts, ts->pids[pmt_pid]);
        }
      }

      if (!ts->pids[pmt_pid]) {
        ts_open_section_filter(ts, pmt_pid, pmt_cb, ts, 1);
      }
      add_pat_entry(ts, sid);
      add_pid_to_pmt(ts, sid, 0); // Add pat pid to program
      add_pid_to_pmt(ts, sid, pmt_pid);
    }
  }
}

int TSParser::handle_packets(TSContext *ts, int64_t nb_packets)
{
  uint8_t packet[TS_MAX_PACKET_SIZE];
  int ret = 0;
  int64_t packet_num = 0;

  if (ts->stream->file->cursor() != ts->last_pos) {
#ifdef XDEBUG
    LOGD("Skipping after seek");
#endif
    // Seek detected, flush pes buffer
    for (unsigned i = 0; i < NB_PID_MAX; ++i) {
      if (ts->pids[i]) {
        if (ts->pids[i]->type == TS_PES) {
          PESContext *pes =
            (PESContext *) ts->pids[i]->u.pes_filter.opaque;
          pes->data_index = 0;
          pes->state = TS_SKIP;
        }
        ts->pids[i]->last_cc = -1;
        ts->pids[i]->last_pcr = -1;
      }
    }
  }

  ts->stop_parse = 0;
  for ( ; ; ) {
    ++packet_num;
    if ((nb_packets != 0 && packet_num >= nb_packets) ||
        ts->stop_parse > 1) {
      ret = -1;
      break;
    }
    if (ts->stop_parse > 0)
      break;

    ret = read_packet(ts, packet);
    if (ret != 0)
      break;
    ret = handle_packet(ts, packet);
    finished_reading_packet(ts);
    if (ret != 0)
      break;
  }
  ts->last_pos = ts->stream->file->cursor();
  return ret;
}

// Handle one TS packet
int TSParser::handle_packet(TSContext *ts, const uint8_t *packet)
{
  TSFilter *tss;
  int len, error_indicator, pid, cc, expected_cc, cc_ok, afc, is_start,
      is_discontinuity, has_adaptation, has_payload;
  const uint8_t *p, *p_end;
  off_t pos;

  /////////////////////////////////////////////////////////////
  /* transport_packet() {
   *     sync_byte  8 bslbf
   *     transport_error_indicator  1  bslbf
   *     payload_unit_start_indicator  1  bslbf
   *     transport_priority  1  bslbf
   *     PID  13 uimsbf
   *     transport_scrambling_control  2  bslbf
   *     adaptation_field_control  2  bslbf
   *     continuity_counter  4  uimsbf
   *     if(adaptation_field_control = ='10' || adaptation_field_control = ='11') {
   *         adaptation_field()
   *     }
   *     if(adaptation_field_control = ='01' || adaptation_field_control = ='11') {
   *         for (i =0; i < N; i++)
   *             data_byte  8  bslbf
   *         }
   *     }
   * } */
  /////////////////////////////////////////////////////////////
  error_indicator = (*(packet + 1) & 0x80);
  if (error_indicator) {
    LOGW("TS packet with transport_error_indicator set found");
    return 0;
  }
  pid = ntohs(*(uint16_t *) (packet + 1)) & 0x1fff;
  is_start = packet[1] & 0x40;
  tss = ts->pids[pid];
  if (!tss) {
    LOGE("No associated filter for pid:0x%x", pid);
    return 0;
  }
  ts->current_pid = pid;

  afc = (packet[3] >> 4) & 3;
  if (afc == 0) // Reserved value
    return 0;
    has_adaptation  = afc & 2;
    has_payload     = afc & 1;
    is_discontinuity= has_adaptation &&
    packet[4] != 0 && // packet[4]: adaption_field_length
    (packet[5] & 0x80); // discontinuity_indicator

    // Continuity check
    cc = (packet[3] & 0xf);
    expected_cc = has_payload ? (tss->last_cc + 1) & 0x0f : tss->last_cc;
    cc_ok = pid == 0x1FFF || // NULL packet PID
    is_discontinuity ||
    tss->last_cc < 0 ||
    expected_cc == cc;

    tss->last_cc = cc;
    if (!cc_ok) {
      LOGE("Continuity check failed for pid:0x%x expected %d got %d",
           pid, expected_cc, cc);
      return -1;
    }

  p = packet + 4;
  if (has_adaptation) {
    int64_t pcr_h;
    int pcr_l;
    if (parse_pcr(&pcr_h, &pcr_l, packet) == 0) {
      tss->last_pcr = pcr_h * 300 + pcr_l;
#ifdef XDEBUG
      LOGI("Filter with pid 0x%x update pcr: %lld (90Hz)",
           tss->pid, tss->last_pcr/300);
#endif
    }
    // Skip adaptation field
    p += p[0] + 1;
  }
  // If past the end of packet, ignore
  p_end = packet + TS_PACKET_SIZE;
  if (p >= p_end || !has_payload)
    return 0;

    pos = ts->stream->file->cursor();

    if (tss->type == TS_SECTION) {
      if (is_start) {
        // Pointer field present
        len = *p++;
        if (p + len > p_end)
          return 0;
        if (len && cc_ok) {
          // Write remaining section bytes
          write_section_data(ts, tss, p, len, 0);
          // Check whether filter has been closed
          if (!ts->pids[pid])
            return 0;
        }
        p += len;
        if (p < p_end) {
          write_section_data(ts, tss, p, p_end - p, 1);
        }
      } else {
        if (cc_ok) {
          write_section_data(ts, tss, p, p_end - p, 0);
        }
      }
    } else {
      int ret;
      // Note: The position here points actually behind the current packet.
      if (tss->type == TS_PES) {
        if ((ret = tss->u.pes_filter.pes_cb(tss, p, p_end - p, is_start,
                                            pos - ts->raw_packet_size)) < 0) {
          return ret;
        }
      }
    }
  return 0;
}

/* return the 90kHz PCR and the extension for the 27MHz PCR. return
 * (-1) if not available */
int TSParser::parse_pcr(int64_t *ppcr_high, int *ppcr_low,
                        const uint8_t *packet)
{
  int afc, len, flags;
  const uint8_t *p;
  unsigned int v;

  afc = (packet[3] >> 4) & 3;
  if (afc <= 1)
    return -1;
  p   = packet + 4;
  len = p[0];
  p++;
  if (len == 0)
    return -1;
  flags = *p++;
  len--;
  if (!(flags & 0x10))
    return -1;
  if (len < 6)
    return -1;
  v          = ntohl(*(uint32_t *) p);
  *ppcr_high = ((int64_t) v << 1) | (p[4] >> 7);
  *ppcr_low  = ((p[4] & 1) << 8) | p[5];
  return 0;
}

// NOTE: buf's size should >= ts->raw_packet_size
int TSParser::read_packet(TSContext *ts, uint8_t *buf)
{
  xfile::File *f = ts->stream->file;
  for ( ; ; ) {
    if (!f->read_buffer(buf, TS_PACKET_SIZE)) {
      if (!f->eof()) {
        LOGE("Read packet from ts file failed");
      }
      return -1;
    }
    // Check packet sync byte
    if (buf[0] != 0x47) {
      LOGE("Found a new packet start(resync not supported)");
      return -1;
    } else {
      break;
    }
  }
  return 0;
}

void TSParser::finished_reading_packet(TSContext *ts)
{
  int skip = ts->raw_packet_size - TS_PACKET_SIZE;
  if (skip > 0) {
    ts->stream->file->seek_ahead(skip);
  }
}

void TSParser::write_section_data(TSContext *ts, TSFilter *tss1,
                                  const uint8_t *buf, int buf_size, int is_start)
{
  TSSectionFilter *tss = &tss1->u.section_filter;
  int len;

  if (is_start) {
    memcpy(tss->section_buf, buf, buf_size);
    tss->section_index = buf_size;
    tss->section_h_size = -1;
    tss->end_of_section_reached = 0;
  } else {
    if (tss->end_of_section_reached)
      return;
    len = 4096 - tss->section_index;
    if (buf_size < len)
      len = buf_size;
    memcpy(tss->section_buf + tss->section_index, buf, len);
    tss->section_index += len;
  }

  // Compute section length if possible
  if (tss->section_h_size == -1 && tss->section_index >= 3) {
    len = (ntohs(* (uint16_t *) (tss->section_buf + 1)) & 0xfff) + 3;
    if (len > 4096)
      return;
    tss->section_h_size = len;
  }

  if (tss->section_h_size != -1 &&
      tss->section_index >= tss->section_h_size) {
    tss->end_of_section_reached = 1;

    if (tss->check_crc) {
      if (crc32(tss->section_buf, tss->section_h_size)) {
        LOGE("crc failed");
        return;
      }
    }
    tss->section_cb(tss1, tss->section_buf, tss->section_h_size);
  }
}

void TSParser::ts_free(TSContext *&ts)
{
  if (!ts) return;

  clear_programs(ts);

  for (unsigned i = 0; i < NB_PID_MAX; ++i) {
    if (ts->pids[i]) {
      ts_close_filter(ts, ts->pids[i]);
    }
  }

  FormatContext *ic = ts->stream;
  flush_packet_queue(ic);
  for (unsigned i = 0; i < ic->nb_streams; ++i) {
    Stream *st = ic->streams[i];
    if (st->parser) {
      parser_close(st->parser);
      st->parser = NULL;
    }
    SAFE_FREE(st->codec);
    SAFE_FREE(st);
  }
  SAFE_FREE(ic->streams);
  SAFE_FREE(ic);

  SAFE_FREE(ts);
}

void TSParser::ts_close_filter(TSContext *ts, TSFilter *filter)
{
  int pid = filter->pid;
  if (filter->type == TS_SECTION) {
    SAFE_FREE(filter->u.section_filter.section_buf);
  } else if (filter->type == TS_PES) {
    PESContext *pes = (PESContext *) filter->u.pes_filter.opaque;
    SAFE_FREE(pes->data);
    SAFE_FREE(pes);
  }

  SAFE_FREE(filter);
  ts->pids[pid] = NULL;
}

int TSParser::parse_section_header(SectionHeader *h,
                                   const uint8_t **pp, const uint8_t *p_end)
{
  int val;

  val = get8(pp, p_end);
  if (val < 0)
    return val;
  h->tid = val;
  *pp += 2; // Including section_length are skipped
  val  = get16(pp, p_end);
  if (val < 0)
    return val;
  h->id = val; // transport_stream_id
  val = get8(pp, p_end);
  if (val < 0)
    return val;
  h->version = (val >> 1) & 0x1f;
  val = get8(pp, p_end);
  if (val < 0)
    return val;
  h->sec_num = val;
  val = get8(pp, p_end);
  if (val < 0)
    return val;
  h->last_sec_num = val;
  return 0;
}

void TSParser::clear_programs(TSContext *ts)
{
  SAFE_FREE(ts->prg);
  ts->nb_prg = 0;
}

void TSParser::clear_program(TSContext *ts, unsigned int programid)
{
  for (unsigned i = 0; i < ts->nb_prg; ++i) {
    if (ts->prg[i].id == programid) {
      ts->prg[i].nb_pids = 0;
      ts->prg[i].pmt_found = 0;
    }
  }
}

void TSParser::pmt_cb(TSFilter *filter,
                      const uint8_t *section, int section_len)
{
  TSContext *ts = (TSContext *) filter->u.section_filter.opaque;
  SectionHeader h1, *h = &h1;
  PESContext *pes;
  Stream *st;
  const uint8_t *p, *p_end;
  int desc_list_len;
  int program_info_length, pcr_pid, pid, stream_type;

  p_end = section + section_len - 4;
  p = section;
  if (parse_section_header(h, &p, p_end) < 0)
    return;

#ifdef XDEBUG
  LOGD("PMT: sid=0x%x sec_num=%d/%d",
       h->id, h->sec_num, h->last_sec_num);
#endif

  if (h->tid != PMT_TID)
    return;

  clear_program(ts, h->id); // Clear previous info of program |h->id|
  pcr_pid = get16(&p, p_end);
  if (pcr_pid < 0)
    return;
  pcr_pid &= 0x1fff;
  add_pid_to_pmt(ts, h->id, pcr_pid);

#ifdef XDEBUG
  LOGD("PMT: pcr_pid=0x%x", pcr_pid);
#endif

  program_info_length = get16(&p, p_end);
  if (program_info_length < 0)
    return;
  program_info_length &= 0xfff;
  if (program_info_length != 0) {
    LOGE("program_info_length not 0, not supported");
    return;
  }
  p += program_info_length;
  if (p >= p_end)
    return;

  // Stop parsing after pmt, we found header
  if (!ts->stream->nb_streams) {
    ts->stop_parse = 2;
  }

  set_pmt_found(ts, h->id);

  for ( ; ; ) {
    st = NULL;
    pes = NULL;
    stream_type = get8(&p, p_end);
    if (stream_type < 0)
      break;
    pid = get16(&p, p_end);
    if (pid < 0)
      return;
    pid &= 0x1fff;
    if (pid == ts->current_pid)
      return;

    // Now create stream
    if (ts->pids[pid] && ts->pids[pid]->type == TS_PES) {
      pes = (PESContext *) ts->pids[pid]->u.pes_filter.opaque;
      if (!pes->st) {
        pes->st = format_new_stream(pes->stream);
        if (!pes->st)
          return;
        pes->st->id = pes->pid;
      }
      st = pes->st;
    } else if (stream_type != 0x13) {
      // ISO/IEC 14496-1 SL-packetized stream or FlexMux stream
      // carried |NOT| in ISO/IEC14496_sections. 
      if (ts->pids[pid]) {
        ts_close_filter(ts, ts->pids[pid]); // Wrongly added sdt filter probably
      }
      pes = add_pes_stream(ts, pid, pcr_pid);
      if (pes) {
        st = format_new_stream(pes->stream);
        if (!st)
          return;
        st->id = pes->pid;
      }
    } else {
      LOGE("Not supported stream_type: 0x%x",
           stream_type);
      return;
    }

    if (!st)
      return;

    if (pes && !pes->stream_type)
      ts_set_stream_info(st, pes, stream_type);

    add_pid_to_pmt(ts, h->id, pid);

    desc_list_len = get16(&p, p_end);
    if (desc_list_len < 0)
      return;
    desc_list_len &= 0xfff;
    p += desc_list_len;
  }

  if (!ts->pids[pcr_pid]) {
    // pcr_pid is transmitted separately
    ts_open_pcr_filter(ts, pcr_pid);
  }
}

void TSParser::add_pat_entry(TSContext *ts, unsigned int programid)
{
  new_program(ts, programid, 0);
}

TSParser::Program *TSParser::get_program(TSContext *ts,
                                         unsigned int programid)
{
  for (unsigned i = 0; i < ts->nb_prg; ++i) {
    if (ts->prg[i].id == programid) {
      return &ts->prg[i];
    }
  }
  return NULL;
}

void TSParser::add_pid_to_pmt(TSContext *ts, unsigned int programid,
                              unsigned int pid)
{
  Program *p = get_program(ts, programid);
  if (!p) {
    LOGE("Program with id: %u not found",
         programid);
    return;
  }

  if (p->nb_pids >= MAX_PIDS_PER_PROGRAM) {
    LOGE("Too many pids for program(id: %u)",
         p->id);
    return;
  }
  p->pids[p->nb_pids++] = pid;
}

TSParser::PESContext *TSParser::add_pes_stream(TSContext *ts,
                                               int pid, int pcr_pid)
{
  TSFilter *tss;
  PESContext *pes;

  // If no pid found, then add a pid context
  pes = (PESContext *) calloc(1, sizeof(PESContext));
  if (!pes)
    return 0; 
  pes->ts      = ts;
  pes->stream  = ts->stream;
  pes->pid     = pid;
  pes->pcr_pid = pcr_pid;
  pes->state   = TS_SKIP;
  pes->pts     = -1;
  pes->dts     = -1;
  tss          = ts_open_pes_filter(ts, pid, ts_push_data, pes);
  if (!tss) {
    SAFE_FREE(pes);
    return 0;
  }       
  return pes;
}

TSParser::TSFilter *TSParser::ts_open_pes_filter(TSContext *ts,
                                                 unsigned int pid, PESCallback *pes_cb, void *opaque)
{
  TSFilter *filter;
  TSPESFilter *pes;

  if (!(filter = ts_open_filter(ts, pid, TS_PES)))
    return NULL;

  pes = &filter->u.pes_filter;
  pes->pes_cb = pes_cb;
  pes->opaque = opaque;
  return filter;
}

int TSParser::ts_push_data(TSFilter *filter,
                           const uint8_t *buf, int buf_size, int is_start,
                           off_t pos)
{
  PESContext *pes = (PESContext *) filter->u.pes_filter.opaque;
  TSContext *ts   = pes->ts;
  const uint8_t *p; 
  int len, code;

  if (is_start) {
    if (pes->state == TS_PAYLOAD && pes->data_index > 0) {
      new_pes_packet(pes, ts->pkt);
      ts->stop_parse = 1;
    } else {
      reset_pes_packet_state(pes);
    }
    pes->state         = TS_HEADER;
    pes->ts_packet_pos = pos;
  }
  p = buf;
  while (buf_size > 0) {
    switch (pes->state) {
      case TS_HEADER:
        len = PES_START_SIZE - pes->data_index;
        if (len > buf_size)
          len = buf_size;
        memcpy(pes->header + pes->data_index, p, len);
        pes->data_index += len;
        p += len;
        buf_size -= len;
        if (pes->data_index == PES_START_SIZE) {
          // We got all the PES or section header. We can now
          // decide
          if (pes->header[0] == 0x00 && pes->header[1] == 0x00 &&
              pes->header[2] == 0x01) {
            // It must be an mpeg2 PES stream
            code = pes->header[3] | 0x100;
            //LOGD("pid=%x pes_code=%#x\n", pes->pid, code);

            if (code == 0x1be) // Padding stream
              goto skip;

            pes->total_size =
              ntohs(* (uint16_t *) (pes->header + 4));
            // NOTE: a zero total size means the PES size is
            // unbounded
            if (!pes->total_size)
              pes->total_size = MAX_PES_PAYLOAD;

            pes->data = (uint8_t *) malloc(pes->total_size);
            if (!pes->data) {
              LOGE("Alloc for pes->data failed: %s",
                   ERRNOMSG);
              return -1;
            }

            if (code != 0x1bc && code != 0x1bf && // program_stream_map, private_stream_2
                code != 0x1f0 && code != 0x1f1 && // ECM, EMM
                code != 0x1ff && code != 0x1f2 && // program_stream_directory, DSMCC_stream
                code != 0x1f8) {                  // ITU-T Rec. H.222.1 type E stream
              pes->state = TS_PESHEADER;
            } else {
              pes->state      = TS_PAYLOAD;
              pes->data_index = 0;
            }
          } else {
            // Otherwise, it should be a table skip packet
skip:
            pes->state = TS_SKIP;
            continue;
          }
        }
        break;
        /**********************************************/
        /* PES packing parsing */
      case TS_PESHEADER:
        len = PES_HEADER_SIZE - pes->data_index;
        if (len < 0)
          return -1;
        if (len > buf_size)
          len = buf_size;
        memcpy(pes->header + pes->data_index, p, len);
        pes->data_index += len;
        p += len;
        buf_size -= len;
        if (pes->data_index == PES_HEADER_SIZE) {
          pes->pes_header_size = pes->header[8] + 9;
          pes->state           = TS_PESHEADER_FILL;
        }
        break;
      case TS_PESHEADER_FILL:
        len = pes->pes_header_size - pes->data_index;
        if (len < 0)
          return -1;
        if (len > buf_size)
          len = buf_size;
        memcpy(pes->header + pes->data_index, p, len);
        pes->data_index += len;
        p += len;
        buf_size -= len;
        if (pes->data_index == pes->pes_header_size) {
          const uint8_t *r;
          unsigned int flags;

          flags = pes->header[7];
          r = pes->header + 9;
          pes->pts = -1;
          pes->dts = -1;
          if ((flags & 0xc0) == 0x80) {
            pes->dts = pes->pts = parse_pes_pts(r);
            r += 5;
          } else if ((flags & 0xc0) == 0xc0) {
            pes->pts = parse_pes_pts(r);
            r += 5;
            pes->dts = parse_pes_pts(r);
            r += 5;
          }
          if (flags & 0x01) { // PES extension
            LOGE("PES extension detected, not supported!");
            return -1;
          } 

          // We got the full header. We parse it and get the payload
          pes->state = TS_PAYLOAD;
          pes->data_index = 0;
          if (pes->stream_type == 0x12 && buf_size > 0) {
            LOGE("Not supported pes stream_type: 0x%x",
                 pes->stream_type);
            return -1;
          }   
          if (pes->stream_type == 0x15 && buf_size >= 5) {
            // Skip metadata access unit header
            pes->pes_header_size += 5;
            p += 5;
            buf_size -= 5;
          }
        }
        break;
      case TS_PAYLOAD:
        if (pes->data) {
          if (pes->data_index > 0 &&
              pes->data_index + buf_size > pes->total_size) {
            new_pes_packet(pes, ts->pkt);
            pes->total_size = MAX_PES_PAYLOAD;
            pes->data = (uint8_t *) malloc(pes->total_size);
            if (!pes->data)
              return -1;
            ts->stop_parse = 1;
          } else if (pes->data_index == 0 &&
              buf_size > pes->total_size) {
            buf_size = pes->total_size;
          }
          memcpy(pes->data + pes->data_index, p, buf_size);
          pes->data_index += buf_size;
          /* Emit complete packets with known packet size
           * decreases demuxer delay for infrequent packets like subtitles from
           * a couple of seconds to milliseconds for properly muxed files.
           * total_size is the number of bytes following pes_packet_length
           * in the pes header, i.e. not counting the first PES_START_SIZE bytes */
          if (!ts->stop_parse && pes->total_size < MAX_PES_PAYLOAD &&
              pes->pes_header_size + pes->data_index == pes->total_size + PES_START_SIZE) {
            new_pes_packet(pes, ts->pkt);
            ts->stop_parse = 1;
          }
        }
        buf_size = 0;
        break;
      case TS_SKIP:
        buf_size = 0;
        break;
    }
  }
  return 0;
}

TSParser::TSFilter *TSParser::ts_open_pcr_filter(TSContext *ts,
                                                 unsigned int pid)
{
  return ts_open_filter(ts, pid, TS_PCR);
}

void TSParser::set_pmt_found(TSContext *ts, unsigned int programid)
{
  Program *p = get_program(ts, programid);
  if (!p) {
    LOGE("Program with id: %u not found",
         programid);
    return;
  }

  p->pmt_found = 1;
}

void TSParser::new_pes_packet(PESContext *pes, Packet *pkt)
{
  uint8_t *p = (uint8_t *) realloc(pkt->data, pes->data_index);
  if (!p) {
    LOGE("realloc for pkt->data failed: %s",
         ERRNOMSG);
  } else {
    bzero(pkt, sizeof(*pkt));
    pkt->size = pes->data_index;
    pkt->data = p;
  }
  memcpy(pkt->data, pes->data, pkt->size);

  if (pes->total_size != MAX_PES_PAYLOAD &&
      pes->pes_header_size + pes->data_index != pes->total_size +
      PES_START_SIZE) {
    LOGE("PES packet size mismatch");
  }
  pkt->stream_index = pes->st->index;
  pkt->pts = pes->pts;
  pkt->dts = pes->dts;
  pkt->pos = pes->ts_packet_pos;
  reset_pes_packet_state(pes);
}

void TSParser::reset_pes_packet_state(PESContext *pes)
{
  pes->pts        = -1;
  pes->dts        = -1;
  pes->data_index = 0;
  SAFE_FREE(pes->data);
}

int64_t TSParser::parse_pes_pts(const uint8_t *buf)
{
  return (int64_t) (*buf & 0x0e) << 29 |
    (ntohs(* (uint16_t *) (buf+1)) >> 1) << 15 |
    ntohs(* (uint16_t *) (buf+3)) >> 1;
}

void TSParser::sdt_cb(TSFilter *filter,
                      const uint8_t *section, int section_len)
{
  TSContext *ts = (TSContext *) filter->u.section_filter.opaque;;
  SectionHeader h1, *h = &h1;
  const uint8_t *p, *p_end, *desc_list_end, *desc_end;
  int onid, val, sid, running_status,
      desc_list_len, desc_tag, desc_len, service_type;
  char *name, *provider_name;

  p_end = section + section_len - 4;
  p     = section;
  if (parse_section_header(h, &p, p_end) < 0)
    return;
  if (h->tid != SDT_TID) // Not sdt actually 
    return;
  onid = get16(&p, p_end);
  if (onid < 0) 
    return;
  val = get8(&p, p_end);
  if (val < 0) 
    return;
  for ( ; ; ) {
    sid = get16(&p, p_end); // Program number
    if (sid < 0) 
      break;
    val = get8(&p, p_end);
    if (val < 0) 
      break;
    desc_list_len = get16(&p, p_end);
    if (desc_list_len < 0) 
      break;
    running_status = (desc_list_len&0xe000)>>13;
    desc_list_len &= 0xfff;
    desc_list_end  = p + desc_list_len;
    if (desc_list_end > p_end)
      break;
    for ( ; ; ) {
      desc_tag = get8(&p, desc_list_end);
      if (desc_tag < 0) 
        break;
      desc_len = get8(&p, desc_list_end);
      desc_end = p + desc_len;
      if (desc_len < 0 || desc_end > desc_list_end)
        break;

#ifdef XDEBUG
      LOGD("SDT: tag: 0x%02x len=%d", desc_tag, desc_len);
#endif

      switch (desc_tag) {
        case 0x48:
          service_type = get8(&p, p_end);
          if (service_type < 0)
            break;
          provider_name = getstr8(&p, p_end);
          if (!provider_name)
            break;
          name = getstr8(&p, p_end);
          if (new_program(ts, sid, running_status)) {
#ifdef XDEBUG
            LOGI("service_name: %s, service_provider: %s",
                 name, provider_name);
#endif
          }
          SAFE_FREE(name);
          SAFE_FREE(provider_name);
          break;
        default:
          break;
      }
      p = desc_end;
    }
    p = desc_list_end;
  }
}

TSParser::Program *TSParser::new_program(TSContext *ts,
                                         unsigned int programid, unsigned int running_status)
{
  Program *p = get_program(ts, programid);
  if (!p) {
    p = (Program *) realloc(ts->prg,
        (ts->nb_prg + 1) * sizeof(*ts->prg));
    if (!p) {
      LOGE("realloc for Program failed: %s",
           ERRNOMSG);
      ts->nb_prg = 0;
      return NULL;
    }
    // Initialize the newly allocated Program
    memset(p + ts->nb_prg, 0, sizeof(Program));
    ts->prg = p;
    p = &ts->prg[ts->nb_prg]; // To the newly allocated one
    ++ts->nb_prg;
    p->id = programid;
  } else {
    // Already found program which added in |sdt_cb|
  }
  p->running_status = running_status;
  return p;
}

int TSParser::ts_set_stream_info(Stream *st, PESContext *pes,
                                 uint32_t stream_type)
{
  priv_set_pts_info(st, 33, 1, 90000);
  st->codec->codec_type = MEDIA_TYPE_UNKNOWN;
  st->codec->codec_id = CODEC_ID_NONE;
  st->need_parsing = 1;
  pes->st = st;
  pes->stream_type = stream_type;

#ifdef XDEBUG
  LOGI("stream=%d stream_type=%x pid=%x",
       st->index, pes->stream_type, pes->pid);
#endif

  const StreamType ISO_types[] = {
    { 0x0f, MEDIA_TYPE_AUDIO, CODEC_ID_AAC  },
    { 0x1b, MEDIA_TYPE_VIDEO, CODEC_ID_H264 },
    { 0 },
  };
  ts_find_stream_type(st, pes->stream_type, ISO_types);
  return 0;
}

void TSParser::ts_find_stream_type(Stream *st,
                                   uint32_t stream_type, const StreamType *types)
{
  for (; types->stream_type; ++types)
    if (stream_type == types->stream_type) {
      st->codec->codec_type = types->codec_type;
      st->codec->codec_id   = types->codec_id;
      return;
    }

  LOGW("stream_type(%x) not supported", stream_type);
}

int64_t TSParser::get_start_time() const
{
  if (m_ts) {
    return m_ts->stream->start_time;
  }
  return -1;
}

int TSParser::ts_read_packet(FormatContext *s, Packet *pkt)
{
  TSContext *ts = (TSContext *) s->priv_data;
  int ret;

  ts->pkt = pkt;
  ret = handle_packets(ts, 0);
  if (ret < 0) {
    SAFE_FREE(pkt->data);
    // Flush pes data left
    for (unsigned i = 0; i < NB_PID_MAX; ++i) {
      if (ts->pids[i] && ts->pids[i]->type == TS_PES) {
        PESContext *pes = (PESContext *) ts->pids[i]->u.pes_filter.opaque;
        if (pes->state == TS_PAYLOAD && pes->data_index > 0) {
          new_pes_packet(pes, pkt);
          pes->state = TS_SKIP;
          ret = 0;
          break;
        }
      }
    }
  }

  if (!ret && pkt->size < 0)
    ret = -1;
  return ret;
}

InputFormat TSParser::mpegts_demuxer = { "mpegts", sizeof(TSContext), ts_read_packet };

}
