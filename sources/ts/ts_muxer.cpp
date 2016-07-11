#include <xlog.h>

#include "ts_muxer.h"
#include "ts_comm.h"

// A PES packet header is generated every DEFAULT_PES_HEADER_FREQ packets
#define DEFAULT_PES_HEADER_FREQ  16
#define DEFAULT_PES_PAYLOAD_SIZE ((DEFAULT_PES_HEADER_FREQ-1)*184+170)

// The section length is 12 bits. The first 2 are set to 0, the remaining
// 10 bits should not exceed 1021.
#define SECTION_LENGTH 1020

#define DEFAULT_PROVIDER_NAME   "dxyh"
#define DEFAULT_SERVICE_NAME    "jwf"

// We retransmit the SI info at this rate
#define SDT_RETRANS_TIME 500
#define PAT_RETRANS_TIME 100
#define PCR_RETRANS_TIME 20

#define PCR_TIME_BASE 27000000

//#define XDEBUG

namespace flvpusher {

static inline void put16(uint8_t **q_ptr, int val)
{
    uint8_t *q;
    q      = *q_ptr;
    *q++   = val >> 8;
    *q++   = val;
    *q_ptr = q;
}

static void putstr8(uint8_t **q_ptr, const char *str)
{
    uint8_t *q;
    int len;

    q = *q_ptr;
    if (!str)
        len = 0;
    else
        len = strlen(str);
    *q++ = len;
    memcpy(q, str, len);
    q     += len;
    *q_ptr = q;
}

/////////////////////////////////////////////////////////////

static uint32_t crc32table[257] = { // CRC_32_IEEE
    0x00000000, 0xB71DC104, 0x6E3B8209, 0xD926430D, 0xDC760413, 0x6B6BC517,
    0xB24D861A, 0x0550471E, 0xB8ED0826, 0x0FF0C922, 0xD6D68A2F, 0x61CB4B2B,
    0x649B0C35, 0xD386CD31, 0x0AA08E3C, 0xBDBD4F38, 0x70DB114C, 0xC7C6D048,
    0x1EE09345, 0xA9FD5241, 0xACAD155F, 0x1BB0D45B, 0xC2969756, 0x758B5652,
    0xC836196A, 0x7F2BD86E, 0xA60D9B63, 0x11105A67, 0x14401D79, 0xA35DDC7D,
    0x7A7B9F70, 0xCD665E74, 0xE0B62398, 0x57ABE29C, 0x8E8DA191, 0x39906095,
    0x3CC0278B, 0x8BDDE68F, 0x52FBA582, 0xE5E66486, 0x585B2BBE, 0xEF46EABA,
    0x3660A9B7, 0x817D68B3, 0x842D2FAD, 0x3330EEA9, 0xEA16ADA4, 0x5D0B6CA0,
    0x906D32D4, 0x2770F3D0, 0xFE56B0DD, 0x494B71D9, 0x4C1B36C7, 0xFB06F7C3,
    0x2220B4CE, 0x953D75CA, 0x28803AF2, 0x9F9DFBF6, 0x46BBB8FB, 0xF1A679FF,
    0xF4F63EE1, 0x43EBFFE5, 0x9ACDBCE8, 0x2DD07DEC, 0x77708634, 0xC06D4730,
    0x194B043D, 0xAE56C539, 0xAB068227, 0x1C1B4323, 0xC53D002E, 0x7220C12A,
    0xCF9D8E12, 0x78804F16, 0xA1A60C1B, 0x16BBCD1F, 0x13EB8A01, 0xA4F64B05,
    0x7DD00808, 0xCACDC90C, 0x07AB9778, 0xB0B6567C, 0x69901571, 0xDE8DD475,
    0xDBDD936B, 0x6CC0526F, 0xB5E61162, 0x02FBD066, 0xBF469F5E, 0x085B5E5A,
    0xD17D1D57, 0x6660DC53, 0x63309B4D, 0xD42D5A49, 0x0D0B1944, 0xBA16D840,
    0x97C6A5AC, 0x20DB64A8, 0xF9FD27A5, 0x4EE0E6A1, 0x4BB0A1BF, 0xFCAD60BB,
    0x258B23B6, 0x9296E2B2, 0x2F2BAD8A, 0x98366C8E, 0x41102F83, 0xF60DEE87,
    0xF35DA999, 0x4440689D, 0x9D662B90, 0x2A7BEA94, 0xE71DB4E0, 0x500075E4,
    0x892636E9, 0x3E3BF7ED, 0x3B6BB0F3, 0x8C7671F7, 0x555032FA, 0xE24DF3FE,
    0x5FF0BCC6, 0xE8ED7DC2, 0x31CB3ECF, 0x86D6FFCB, 0x8386B8D5, 0x349B79D1,
    0xEDBD3ADC, 0x5AA0FBD8, 0xEEE00C69, 0x59FDCD6D, 0x80DB8E60, 0x37C64F64,
    0x3296087A, 0x858BC97E, 0x5CAD8A73, 0xEBB04B77, 0x560D044F, 0xE110C54B,
    0x38368646, 0x8F2B4742, 0x8A7B005C, 0x3D66C158, 0xE4408255, 0x535D4351,
    0x9E3B1D25, 0x2926DC21, 0xF0009F2C, 0x471D5E28, 0x424D1936, 0xF550D832,
    0x2C769B3F, 0x9B6B5A3B, 0x26D61503, 0x91CBD407, 0x48ED970A, 0xFFF0560E,
    0xFAA01110, 0x4DBDD014, 0x949B9319, 0x2386521D, 0x0E562FF1, 0xB94BEEF5,
    0x606DADF8, 0xD7706CFC, 0xD2202BE2, 0x653DEAE6, 0xBC1BA9EB, 0x0B0668EF,
    0xB6BB27D7, 0x01A6E6D3, 0xD880A5DE, 0x6F9D64DA, 0x6ACD23C4, 0xDDD0E2C0,
    0x04F6A1CD, 0xB3EB60C9, 0x7E8D3EBD, 0xC990FFB9, 0x10B6BCB4, 0xA7AB7DB0,
    0xA2FB3AAE, 0x15E6FBAA, 0xCCC0B8A7, 0x7BDD79A3, 0xC660369B, 0x717DF79F,
    0xA85BB492, 0x1F467596, 0x1A163288, 0xAD0BF38C, 0x742DB081, 0xC3307185,
    0x99908A5D, 0x2E8D4B59, 0xF7AB0854, 0x40B6C950, 0x45E68E4E, 0xF2FB4F4A,
    0x2BDD0C47, 0x9CC0CD43, 0x217D827B, 0x9660437F, 0x4F460072, 0xF85BC176,
    0xFD0B8668, 0x4A16476C, 0x93300461, 0x242DC565, 0xE94B9B11, 0x5E565A15,
    0x87701918, 0x306DD81C, 0x353D9F02, 0x82205E06, 0x5B061D0B, 0xEC1BDC0F,
    0x51A69337, 0xE6BB5233, 0x3F9D113E, 0x8880D03A, 0x8DD09724, 0x3ACD5620,
    0xE3EB152D, 0x54F6D429, 0x7926A9C5, 0xCE3B68C1, 0x171D2BCC, 0xA000EAC8,
    0xA550ADD6, 0x124D6CD2, 0xCB6B2FDF, 0x7C76EEDB, 0xC1CBA1E3, 0x76D660E7,
    0xAFF023EA, 0x18EDE2EE, 0x1DBDA5F0, 0xAAA064F4, 0x738627F9, 0xC49BE6FD,
    0x09FDB889, 0xBEE0798D, 0x67C63A80, 0xD0DBFB84, 0xD58BBC9A, 0x62967D9E,
    0xBBB03E93, 0x0CADFF97, 0xB110B0AF, 0x060D71AB, 0xDF2B32A6, 0x6836F3A2,
    0x6D66B4BC, 0xDA7B75B8, 0x035D36B5, 0xB440F7B1, 0x00000001
};

static uint32_t crc32(const uint32_t *ctx, uint32_t crc,
        const uint8_t *buffer, size_t length){
    const uint8_t *end = buffer + length;

    while(buffer < end)
        crc = ctx[((uint8_t)crc) ^ *buffer++] ^ (crc >> 8);

    return crc;
}

/////////////////////////////////////////////////////////////

TSMuxer::TSMuxer() :
    m_ic(NULL), m_file(NULL)
{
    m_file = new xfile::File;
}

TSMuxer::~TSMuxer()
{
    ts_free(m_ic);

    SAFE_DELETE(m_file);
}

bool TSMuxer::is_opened() const
{
    return m_file->is_opened();
}

int TSMuxer::set_file(const std::string &tspath, AVRational itime_base)
{
    if (!m_file->open(tspath, "wb"))
        return -1;

    if (init(itime_base) < 0) {
        LOGE("ts_muxer's init() failed");
        return -1;
    }
    return 0;
}

int TSMuxer::init(AVRational itime_base)
{
    if (ts_init(m_ic, m_file) < 0)
        return -1;

    TSWrite *ts = (TSWrite *) m_ic->priv_data;
    TSWriteStream *ts_st;
    Stream *st, *pcr_st = NULL;
    const char *service_name;
    const char *provider_name;
    TSService *service;
    int *pids = NULL;
    int ret = 0;

    if (m_ic->max_delay < 0)
        m_ic->max_delay = 0;

    // Round up to a whole number of TS packets
    ts->pes_payload_size = (ts->pes_payload_size+14+183)/184*184-14;

    ts->tsid = ts->transport_stream_id;
    ts->onid = ts->original_network_id;
    service_name = DEFAULT_SERVICE_NAME;
    provider_name = DEFAULT_PROVIDER_NAME;
    service = ts_add_service(ts, ts->service_id,
                             provider_name, service_name);

    if (!service)
        return -1;

    service->pmt.write_packet = section_write_packet;
    service->pmt.opaque       = m_ic;
    service->pmt.cc           = 15;

    ts->pat.pid          = PAT_PID;
    ts->pat.cc           = 15;
    ts->pat.write_packet = section_write_packet;
    ts->pat.opaque       = m_ic;

    ts->sdt.pid          = SDT_PID;
    ts->sdt.cc           = 15;
    ts->sdt.write_packet = section_write_packet;
    ts->sdt.opaque       = m_ic;

    pids = (int *) calloc(m_ic->nb_streams, sizeof(*pids));
    if (!pids) {
        ret = -1;
        goto bail;
    }

    for (unsigned i = 0; i < m_ic->nb_streams; ++i) {
        st = m_ic->streams[i];

        ts_st = (TSWriteStream *) calloc(1, sizeof(TSWriteStream));
        if (!ts_st) {
            return -1;
            goto bail;
        }
        st->priv_data = ts_st;

        ts_st->user_tb = itime_base;
        priv_set_pts_info(st, 33, 1, 90000);

        ts_st->payload = (uint8_t *) calloc(1, ts->pes_payload_size);
        if (!ts_st->payload) {
            ret = -1;
            goto bail;
        }
        ts_st->service = service;
        // MPEG pid values < 16 are reserved. Applications which set st->id in
        // this range are assigned a calculated pid.
        if (st->id < 16) {
            ts_st->pid = ts->start_pid + i;
        } else if (st->id < 0x1FFF) {
            ts_st->pid = st->id;
        } else {
            LOGE("Invalid stream id %d, must be less than 8191", st->id);
            ret = -1;
            goto bail;
        }
        if (ts_st->pid == service->pmt.pid) {
            LOGE("Duplicate stream id %d", ts_st->pid);
            ret = -1;
            goto bail;
        }
        for (unsigned j = 0; j < i; j++) {
            if (pids[j] == ts_st->pid) {
                LOGE("Duplicate stream id %d", ts_st->pid);
                ret = -1;
                goto bail;
            }
        }
        pids[i]                = ts_st->pid;
        ts_st->payload_pts     = -1;
        ts_st->payload_dts     = -1;
        ts_st->first_pts_check = 1;
        ts_st->cc              = 15;
        // Update PCR pid by using the first video stream
        if (st->codec->codec_type == MEDIA_TYPE_VIDEO &&
            service->pcr_pid == 0x1fff) {
            service->pcr_pid = ts_st->pid;
            pcr_st           = st;
        }
    }

    SAFE_FREE(pids);

    // If no video stream, use the first stream as PCR
    if (service->pcr_pid == 0x1fff && m_ic->nb_streams > 0) {
        pcr_st           = m_ic->streams[0];
        ts_st            = (TSWriteStream *) pcr_st->priv_data;
        service->pcr_pid = ts_st->pid;
    } else
        ts_st = (TSWriteStream *) pcr_st->priv_data;

    if (ts->mux_rate > 1) {
        service->pcr_packet_period = (ts->mux_rate * ts->pcr_period) /
            (TS_PACKET_SIZE * 8 * 1000);
        ts->sdt_packet_period      = (ts->mux_rate * SDT_RETRANS_TIME) /
            (TS_PACKET_SIZE * 8 * 1000);
        ts->pat_packet_period      = (ts->mux_rate * PAT_RETRANS_TIME) /
            (TS_PACKET_SIZE * 8 * 1000);

        if (ts->copyts < 1)
            ts->first_pcr = av_rescale(m_ic->max_delay, PCR_TIME_BASE, AV_TIME_BASE);
    } else {
        // Arbitrary values, PAT/PMT will also be written on video key frames
        ts->sdt_packet_period = 200;
        ts->pat_packet_period = 40;
        if (pcr_st->codec->codec_type == MEDIA_TYPE_AUDIO) {
            service->pcr_packet_period = 44100 / (10 * 1024); // NOTE: Hard coded
        } else {
            // Max delta PCR 0.1s
            service->pcr_packet_period =
                ts_st->user_tb.den / (10 * ts_st->user_tb.num);
        }
        if (!service->pcr_packet_period)
            service->pcr_packet_period = 1;
    }

    // Output a PCR as soon as possible
    service->pcr_packet_count = service->pcr_packet_period;
    ts->pat_packet_count      = ts->pat_packet_period - 1;
    ts->sdt_packet_count      = ts->sdt_packet_period - 1;

#ifdef XDEBUG
    {
    char tmp[1024];
    int off = 0;
    if (ts->mux_rate == 1)
        off += snprintf(tmp+off, sizeof(tmp)-off-1, "Muxrate VBR, ");
    else
        off += snprintf(tmp+off, sizeof(tmp)-off-1, "Muxrate %d, ", ts->mux_rate);
    snprintf(tmp+off, sizeof(tmp)-off-1,
            "pcr every %d pkts, sdt every %d pkts, pat/pmt every %d pkts",
            service->pcr_packet_period,
            ts->sdt_packet_period, ts->pat_packet_period);
    LOGD(tmp);
    }
#endif

    if (ts->m2ts_mode == -1) {
        if (end_with(m_file->get_path(), ".m2ts"))
            ts->m2ts_mode = 1;
        else
            ts->m2ts_mode = 0;
    }
    return 0;

bail:
    SAFE_FREE(pids);
    for (unsigned i = 0; i < m_ic->nb_streams; ++i) {
        st      = m_ic->streams[i];
        ts_st   = (TSWriteStream *) st->priv_data;
        if (ts_st) {
            SAFE_FREE(ts_st->payload);
        }
        SAFE_FREE(ts_st);
    }

    for (int i = 0; i < ts->nb_services; ++i) {
        service = ts->services[i];
        SAFE_FREE(service->provider_name);
        SAFE_FREE(service->name);
        SAFE_FREE(service);
    }
    SAFE_FREE(ts->services);
    return ret;
}

int TSMuxer::ts_init(FormatContext *&ic, xfile::File *f)
{
    TSWrite *ts;

    ic = (FormatContext *) calloc(1, sizeof(FormatContext));
    if (!ic) {
        LOGE("calloc for FormatContext failed: %s",
                ERRNOMSG);
        return -1;
    }
    ic->start_time = -1;
    ic->file = f;
    ic->max_interleave_delta = 10000000;
    ic->otime_base = (AVRational) { 1, 1000 };
    ic->max_delay = 700000;
    ic->oformat = &ts_muxer;
    if (ic->oformat->priv_data_size > 0) {
        ic->priv_data = calloc(1, ic->oformat->priv_data_size);
        if (!ic->priv_data) goto bail;
    }
    for (unsigned i = 0; i < STRM_NUM; ++i) { // Add 2 streams for V/A
        Stream *st = format_new_stream(ic);
        if (!st) goto bail;

        st->time_base = (AVRational) { 1, 1000 };
        st->id = i;
        // Assume stream:0 is video stream, stream:1 audio stream
        if (i == VIDEO) {
            st->codec->codec_type = MEDIA_TYPE_VIDEO;
            st->codec->codec_id = CODEC_ID_H264;
        } else {
            st->codec->codec_type = MEDIA_TYPE_AUDIO;
            st->codec->codec_id = CODEC_ID_AAC;
        }
    }

    ts = (TSWrite *) ic->priv_data;
    ts->pes_payload_size = DEFAULT_PES_PAYLOAD_SIZE;
    ts->transport_stream_id = 0x0001;
    ts->original_network_id = 0x0001;
    ts->service_id = 0x0001;
    ts->pmt_start_pid = 0x1000;
    ts->start_pid = 0x0100;
    ts->mux_rate = 1;
    ts->pcr_period = PCR_RETRANS_TIME;
    ts->copyts = -1;
    ts->m2ts_mode = -1;
    ts->tables_version = 0;
    ts->omit_video_pes_length = 1;
    return 0;

bail:
    if (ic) SAFE_FREE(ic->priv_data);
    SAFE_FREE(ic);
    return -1;
}

void TSMuxer::ts_free(FormatContext *&ic)
{
    if (!ic) return;

    ts_write_flush(ic);

    for (unsigned i = 0; i < m_ic->nb_streams; ++i) {
        Stream *st           = ic->streams[i];
        TSWriteStream *ts_st = (TSWriteStream *) st->priv_data;
        if (ts_st) {
            SAFE_FREE(ts_st->payload);
        }
        SAFE_FREE(ts_st);
    }

    TSWrite *ts = (TSWrite *) ic->priv_data;
    for (int i = 0; i < ts->nb_services; ++i) {
        TSService *service = ts->services[i];
        SAFE_FREE(service->provider_name);
        SAFE_FREE(service->name);
        SAFE_FREE(service);
    }
    SAFE_FREE(ts->services);

    flush_packet_queue(m_ic);
    for (unsigned i = 0; i < m_ic->nb_streams; ++i) {
        Stream *st = ic->streams[i];
        if (st->parser) {
            parser_close(st->parser);
            st->parser = NULL;
        }
        SAFE_FREE(st->codec);
        SAFE_FREE(st);
    }
    SAFE_FREE(m_ic->streams);
    SAFE_FREE(ic);

    SAFE_FREE(ts);
}

TSMuxer::TSService *TSMuxer::ts_add_service(TSWrite *ts, int sid,
        const char *provider_name, const char *service_name)
{
    TSService *service;

    service = (TSService *) calloc(1, sizeof(TSService));
    if (!service)
        return NULL;
    service->pmt.pid        = ts->pmt_start_pid + ts->nb_services;
    service->sid            = sid;
    service->pcr_pid        = 0x1fff;
    service->provider_name  = strdup(provider_name);
    service->name           = strdup(service_name);
    if (!service->provider_name || !service->name)
        goto bail;
    ts->services = (TSService **) realloc(ts->services,
            (ts->nb_services+1)*sizeof(TSService *));
    ts->services[ts->nb_services++] = service;
    return service;

bail:
    SAFE_FREE(service->provider_name);
    SAFE_FREE(service->name);
    SAFE_FREE(service);
    return NULL;
}

int TSMuxer::write_frame(const int32_t ts,
        const uint8_t *dat, const uint32_t dat_len, int is_video)
{
    Packet pkt1, *pkt=&pkt1;
    pkt->data = (uint8_t *) malloc(dat_len * sizeof(uint8_t));
    if (!pkt->data) {
        LOGE("malloc for pkt's data failed:%s",
                ERRNOMSG);
        return -1;
    }
    memcpy(pkt->data, dat, dat_len);
    pkt->size = dat_len;
    pkt->pts = pkt->dts = ts;
    pkt->pos = 0;
    pkt->stream_index = is_video ? VIDEO : AUDIO;
    pkt->duration = 0;
    int ret = ts_write_packet_internal(m_ic, pkt);
    SAFE_FREE(pkt->data);
    return ret;
}

int TSMuxer::ts_write_packet_internal(FormatContext *s, Packet *pkt)
{
    Stream *st = s->streams[pkt->stream_index];
    int size = pkt->size;
    uint8_t *buf = pkt->data;
    uint8_t *data = NULL;
    TSWrite *ts = (TSWrite *) s->priv_data;
    TSWriteStream *ts_st = (TSWriteStream *) st->priv_data;
    const int64_t delay = av_rescale(s->max_delay, 90000, AV_TIME_BASE) * 2;
    int64_t dts = pkt->dts, pts = pkt->pts;
    int flags = 0;

    // Conv pts,dts from timebase={1,1000}(that is ms) to {1, 90000}
    pts = av_rescale(pts, 90000, 1000);
    dts = av_rescale(dts, 90000, 1000);

    if (ts->reemit_pat_pmt) {
        ts->reemit_pat_pmt = 0;
        ts->flags |= MPEGTS_FLAG_REEMIT_PAT_PMT;
    }

    if (ts->flags & MPEGTS_FLAG_REEMIT_PAT_PMT) {
        ts->pat_packet_count = ts->pat_packet_period - 1;
        ts->sdt_packet_count = ts->sdt_packet_period - 1;
        ts->flags           &= ~MPEGTS_FLAG_REEMIT_PAT_PMT;
    }

    if (ts->copyts < 1) {
        if (pts != -1)
            pts += delay;
        if (dts != -1)
            dts += delay;
    }

    if (ts_st->first_pts_check && pts == -1) {
        LOGE("First pts value must be set");
        return -1;
    }
    ts_st->first_pts_check = 0;

    if (st->codec->codec_id == CODEC_ID_H264) {
        const uint8_t *p = buf, *buf_end = p + size;
        uint32_t state = -1;
        int ret = check_h264_startcode(pkt);
        if (ret < 0)
            return ret;

        do {
            p = priv_find_start_code(p, buf_end, &state);
            if ((state&0x1f) == 7 || (state&0x1f) == 8) {
                // We got a key-frame
                flags = AV_PKT_FLAG_KEY;
            }
        } while (p < buf_end && (state & 0x1f) != 9 &&
                (state & 0x1f) != 5 && (state & 0x1f) != 1);

        if ((state & 0x1f) != 9) { // AUD NAL
            data = (uint8_t *) malloc(pkt->size + 6);
            if (!data)
                return -1;
            memcpy(data + 6, pkt->data, pkt->size);
            put_be32(data, 0x00000001);
            data[4] = 0x09;     
            data[5] = 0xf0; // Any slice type (0xe) + rbsp stop one bit
            buf     = data;
            size    = pkt->size + 6;
        }
    } else if (st->codec->codec_id == CODEC_ID_AAC) {
        flags = AV_PKT_FLAG_KEY;
        if (pkt->size < 2) {
            LOGE("AAC packet too short");
            return -1;
        }
        if ((ENTOHS(*(uint16_t*)pkt->data)&0xfff0) != 0xfff0) {
            if (!ts_st->amux) {
                LOGE("AAC bitstream not in ADTS format");
                return -1;
            }
        }
    } else {
        LOGE("stream codec_id:%d not supported",
                st->codec->codec_id);
        return -1;
    }

    if (pkt->dts != -1) {
        for (unsigned i = 0; i < s->nb_streams; ++i) {
            Stream *st2 = s->streams[i];
            TSWriteStream *ts_st2 = (TSWriteStream *) st2->priv_data;
            if (   ts_st2->payload_size
               && (ts_st2->payload_dts == -1 || dts - ts_st2->payload_dts > delay/2)) {
                ts_write_pes(s, st2, ts_st2->payload, ts_st2->payload_size,
                        ts_st2->payload_pts, ts_st2->payload_dts,
                        ts_st2->payload_flags & AV_PKT_FLAG_KEY);
                ts_st2->payload_size = 0;
            }
        }
    }

    if (ts_st->payload_size && ts_st->payload_size + size > ts->pes_payload_size) {
        ts_write_pes(s, st, ts_st->payload, ts_st->payload_size,
                ts_st->payload_pts, ts_st->payload_dts,
                ts_st->payload_flags & AV_PKT_FLAG_KEY);
        ts_st->payload_size = 0;
    }

    if (st->codec->codec_type != MEDIA_TYPE_AUDIO || size > ts->pes_payload_size) {
        assert(!ts_st->payload_size);
        // For video and subtitle, write a single pes packet
        ts_write_pes(s, st, buf, size, pts, dts,
                flags & AV_PKT_FLAG_KEY);
        SAFE_FREE(data);
        return 0;
    }

    if (!ts_st->payload_size) {
        ts_st->payload_pts   = pts;
        ts_st->payload_dts   = dts;
        ts_st->payload_flags = flags;
    }

    memcpy(ts_st->payload + ts_st->payload_size, buf, size);
    ts_st->payload_size += size;

    SAFE_FREE(data);
    return 0;
}

void TSMuxer::ts_write_pes(FormatContext *s, Stream *st,
        const uint8_t *payload, int payload_size,
        int64_t pts, int64_t dts, int key)
{
    TSWriteStream *ts_st = (TSWriteStream *) st->priv_data;
    TSWrite *ts = (TSWrite *) s->priv_data; 
    uint8_t buf[TS_PACKET_SIZE];
    uint8_t *q;
    int val, is_start, len, header_len, write_pcr, is_dvb_subtitle, is_dvb_teletext, flags;
    int afc_len, stuffing_len;
    int64_t pcr = -1;
    int64_t delay = av_rescale(s->max_delay, 90000, AV_TIME_BASE);
    int force_pat = st->codec->codec_type == MEDIA_TYPE_VIDEO && key && !ts_st->prev_payload_key;

    is_start = 1;
    while (payload_size > 0) {
        retransmit_si_info(s, force_pat);
        force_pat = 0;

        write_pcr = 0;
        if (ts_st->pid == ts_st->service->pcr_pid) {
            if (ts->mux_rate > 1 || is_start) // VBR pcr period is based on frames
                ts_st->service->pcr_packet_count++;
            if (ts_st->service->pcr_packet_count >=
                ts_st->service->pcr_packet_period) {
                ts_st->service->pcr_packet_count = 0;
                write_pcr = 1; 
            }
        }

        if (ts->mux_rate > 1 && dts != -1 &&
            (dts - get_pcr(ts, s->file) / 300) > delay) {
            // pcr insert gets priority over null packet insert
            if (write_pcr)
                ts_insert_pcr_only(s, st);
            else
                ts_insert_null_packet(s);
            // Recalculate write_pcr and possibly retransmit si_info
            continue; 
        }

        // Prepare packet header
        q    = buf;
        *q++ = 0x47;
        val  = ts_st->pid >> 8;
        if (is_start)
            val |= 0x40;
        *q++      = val;
        *q++      = ts_st->pid;
        ts_st->cc = (ts_st->cc + 1) & 0xf;
        *q++      = 0x10 | ts_st->cc; // Payload indicator + CC
        if (key && is_start && pts != -1) {
            // Set Random Access for key frames
            if (ts_st->pid == ts_st->service->pcr_pid)
                write_pcr = 1;
            set_af_flag(buf, 0x40);
            q = get_ts_payload_start(buf);
        }
        if (write_pcr) {
            set_af_flag(buf, 0x10);
            q = get_ts_payload_start(buf);
            // Add 11, pcr references the last byte of program clock reference base
            if (ts->mux_rate > 1)
                pcr = get_pcr(ts, s->file);
            else
                pcr = (dts - delay) * 300;
            if (dts != -1 && dts < pcr / 300)
                LOGE("dts < pcr, TS is invalid");
            extend_af(buf, write_pcr_bits(q, pcr));
            q = get_ts_payload_start(buf);
        }
        if (is_start) {
            int pes_extension = 0;
            int pes_header_stuffing_bytes = 0;

            UNUSED(pes_extension);
            UNUSED(pes_header_stuffing_bytes);

            // Write PES header
            *q++ = 0x00;
            *q++ = 0x00;
            *q++ = 0x01;
            is_dvb_subtitle = 0;
            is_dvb_teletext = 0;
            if (st->codec->codec_type == MEDIA_TYPE_VIDEO)
                *q++ = 0xe0;
            else if (st->codec->codec_type == MEDIA_TYPE_AUDIO &&
                     st->codec->codec_id == CODEC_ID_AAC)
                *q++ = 0xc0;
            header_len = 0;
            flags      = 0;
            if (pts != -1) {
                header_len += 5;
                flags      |= 0x80;
            }
            if (dts != -1 && pts != -1 && dts != pts) {
                header_len += 5;
                flags      |= 0x40;
            }
            len = payload_size + header_len + 3;
            if (len > 0xffff)
                len = 0;
            if (ts->omit_video_pes_length && st->codec->codec_type == MEDIA_TYPE_VIDEO) {
                len = 0;
            }
            *q++ = len >> 8;
            *q++ = len;
            val  = 0x80;
            *q++ = val;
            *q++ = flags;
            *q++ = header_len;
            if (pts != -1) {
                write_pts(q, flags >> 6, pts);
                q += 5;
            }
            if (dts != -1 && pts != -1 && dts != pts) {
                write_pts(q, 1, dts);
                q += 5;
            }
            is_start = 0;
        }
        // Header size
        header_len = q - buf;
        // Data len
        len = TS_PACKET_SIZE - header_len;
        if (len > payload_size)
            len = payload_size;
        stuffing_len = TS_PACKET_SIZE - header_len - len;
        if (stuffing_len > 0) {
            // Add stuffing with AFC
            if (buf[3] & 0x20) {
                // Stuffing already present: increase its size
                afc_len = buf[4] + 1;
                memmove(buf + 4 + afc_len + stuffing_len,
                        buf + 4 + afc_len,
                        header_len - (4 + afc_len));
                buf[4] += stuffing_len;
                memset(buf + 4 + afc_len, 0xff, stuffing_len);
            } else {
                // Add stuffing
                memmove(buf + 4 + stuffing_len, buf + 4, header_len - 4);
                buf[3] |= 0x20;
                buf[4]  = stuffing_len - 1;
                if (stuffing_len >= 2) {
                    buf[5] = 0x00;
                    memset(buf + 6, 0xff, stuffing_len - 2);
                }
            }
        }

        memcpy(buf + TS_PACKET_SIZE - len, payload, len);

        payload      += len;
        payload_size -= len;
        ts_prefix_m2ts_header(s);
        s->file->write_buffer(buf, TS_PACKET_SIZE);
    }
    ts_st->prev_payload_key = key;
}

void TSMuxer::write_pts(uint8_t *q, int fourbits, int64_t pts)
{               
    int val;

    val  = fourbits << 4 | (((pts >> 30) & 0x07) << 1) | 1;
    *q++ = val;  
    val  = (((pts >> 15) & 0x7fff) << 1) | 1;
    *q++ = val >> 8;
    *q++ = val; 
    val  = (((pts) & 0x7fff) << 1) | 1;
    *q++ = val >> 8;
    *q++ = val;
}

// Extend the adaptation field by size bytes
void TSMuxer::extend_af(uint8_t *pkt, int size)
{           
    // Expect already existing adaptation field
    assert(pkt[3] & 0x20);
    pkt[4] += size;
}

// Set an adaptation field flag in an MPEG-TS packet
void TSMuxer::set_af_flag(uint8_t *pkt, int flag)
{       
    // Expect at least one flag to set
    assert(flag);
        
    if ((pkt[3] & 0x20) == 0) {
        // No AF yet, set adaptation field flag
        pkt[3] |= 0x20;
        // 1 byte length, no flags
        pkt[4] = 1;
        pkt[5] = 0;
    }
    pkt[5] |= flag;
}

// Get a pointer to MPEG-TS payload (right after TS packet header)
uint8_t *TSMuxer::get_ts_payload_start(uint8_t *pkt)
{           
    if (pkt[3] & 0x20)
        return pkt + 5 + pkt[4];
    else        
        return pkt + 4;
}

// Write a single null transport stream packet
void TSMuxer::ts_insert_null_packet(FormatContext *s)
{           
    uint8_t *q; 
    uint8_t buf[TS_PACKET_SIZE];

    q    = buf;
    *q++ = 0x47;
    *q++ = 0x00 | 0x1f;
    *q++ = 0xff;
    *q++ = 0x10;
    memset(q, 0x0FF, TS_PACKET_SIZE - (q - buf));
    ts_prefix_m2ts_header(s);
    s->file->write_buffer(buf, TS_PACKET_SIZE);
}

void TSMuxer::ts_insert_pcr_only(FormatContext *s, Stream *st)
{
    TSWrite *ts = (TSWrite *) s->priv_data;
    TSWriteStream *ts_st = (TSWriteStream *) st->priv_data;
    uint8_t *q;
    uint8_t buf[TS_PACKET_SIZE];

    q    = buf;
    *q++ = 0x47;
    *q++ = ts_st->pid >> 8;
    *q++ = ts_st->pid;
    *q++ = 0x20 | ts_st->cc;   // Adaptation only
    // Continuity Count field does not increment (see 13818-1 section 2.4.3.3)
    *q++ = TS_PACKET_SIZE - 5; // Adaptation Field Length
    *q++ = 0x10;               // Adaptation flags: PCR present

    // PCR coded into 6 bytes
    q += write_pcr_bits(q, get_pcr(ts, s->file));

    // Stuffing bytes
    memset(q, 0xFF, TS_PACKET_SIZE - (q - buf));
    ts_prefix_m2ts_header(s);
    s->file->write_buffer(buf, TS_PACKET_SIZE);
}

int64_t TSMuxer::get_pcr(const TSWrite *ts, xfile::File *f)
{
    return av_rescale(f->cursor() + 11, 8 * PCR_TIME_BASE, ts->mux_rate) +
        ts->first_pcr;
}

int TSMuxer::write_pcr_bits(uint8_t *buf, int64_t pcr)
{
    int64_t pcr_low = pcr % 300, pcr_high = pcr / 300;

    *buf++ = pcr_high >> 25;
    *buf++ = pcr_high >> 17;
    *buf++ = pcr_high >>  9;
    *buf++ = pcr_high >>  1;
    *buf++ = pcr_high <<  7 | pcr_low >> 8 | 0x7e;
    *buf++ = pcr_low;

    return 6;
}

void TSMuxer::ts_prefix_m2ts_header(FormatContext *s)
{
    TSWrite *ts = (TSWrite *) s->priv_data;
    if (ts->m2ts_mode) {
        int64_t pcr = get_pcr(ts, s->file);
        uint32_t tp_extra_header = pcr % 0x3fffffff;
        tp_extra_header = ENTOHL(*(uint32_t*)(&tp_extra_header));
        s->file->write_buffer((unsigned char *) &tp_extra_header,
                sizeof(tp_extra_header));
    }
}

void TSMuxer::retransmit_si_info(FormatContext *s, int force_pat)
{
    TSWrite *ts = (TSWrite *) s->priv_data;
    int i;

    if (++ts->sdt_packet_count == ts->sdt_packet_period) {
        ts->sdt_packet_count = 0;
        ts_write_sdt(s);
    }       
    if (++ts->pat_packet_count == ts->pat_packet_period || force_pat) {
        ts->pat_packet_count = 0;
        ts_write_pat(s);
        for (i = 0; i < ts->nb_services; i++)
            ts_write_pmt(s, ts->services[i]);
    }
}

void TSMuxer::ts_write_sdt(FormatContext *s)
{
    TSWrite *ts = (TSWrite *) s->priv_data;
    TSService *service;
    uint8_t data[SECTION_LENGTH], *q, *desc_list_len_ptr, *desc_len_ptr;
    int i, running_status, free_ca_mode, val;

    q = data;
    put16(&q, ts->onid);
    *q++ = 0xff;
    for (i = 0; i < ts->nb_services; i++) {
        service = ts->services[i];
        put16(&q, service->sid); 
        *q++              = 0xfc | 0x00; // Currently no EIT info
        desc_list_len_ptr = q;
        q                += 2;
        running_status    = 4; // running
        free_ca_mode      = 0;

        // Write only one descriptor for the service name and provider
        *q++         = 0x48;
        desc_len_ptr = q;
        q++;
        *q++         = 0x01; // Digital television service
        putstr8(&q, service->provider_name);
        putstr8(&q, service->name);
        desc_len_ptr[0] = q - desc_len_ptr - 1;

        // Fill descriptor length
        val = (running_status << 13) | (free_ca_mode << 12) |
            (q - desc_list_len_ptr - 2);
        desc_list_len_ptr[0] = val >> 8;
        desc_list_len_ptr[1] = val;
    }   
    ts_write_section1(&ts->sdt, SDT_TID, ts->tsid, ts->tables_version, 0, 0,
            data, q - data);
}

void TSMuxer::ts_write_pat(FormatContext *s)
{
    TSWrite *ts = (TSWrite *) s->priv_data;
    TSService *service;
    uint8_t data[SECTION_LENGTH], *q;
    int i;

    q = data;
    for (i = 0; i < ts->nb_services; i++) {
        service = ts->services[i];
        put16(&q, service->sid);
        put16(&q, 0xe000 | service->pmt.pid);
    }
    ts_write_section1(&ts->pat, PAT_TID, ts->tsid, ts->tables_version, 0, 0,
            data, q - data);
}

int TSMuxer::ts_write_pmt(FormatContext *s, TSService *service)
{
    TSWrite *ts = (TSWrite *) s->priv_data;
    uint8_t data[SECTION_LENGTH], *q, *desc_length_ptr, *program_info_length_ptr;
    int val, stream_type, err = 0;
    unsigned i;

    q = data;
    put16(&q, 0xe000 | service->pcr_pid);

    program_info_length_ptr = q;
    q += 2;

    /* put program info here */

    val = 0xf000 | (q - program_info_length_ptr - 2);
    program_info_length_ptr[0] = val >> 8;
    program_info_length_ptr[1] = val;

    for (i = 0; i < s->nb_streams; ++i) {
        Stream *st = s->streams[i];
        TSWriteStream *ts_st = (TSWriteStream *) st->priv_data;

        if (q - data > SECTION_LENGTH - 32) {
            err = 1;
            break;
        }
        switch (st->codec->codec_id) {
        case CODEC_ID_H264:
            stream_type = STREAM_TYPE_VIDEO_H264;
            break;

        case CODEC_ID_AAC:
            stream_type = STREAM_TYPE_AUDIO_AAC;
            break;

        default:
            LOGE("Unsupported codec_id: %d", st->codec->codec_id);
            err = 1;
            break;
        }

        if (err)
            break;

        *q++ = stream_type;
        put16(&q, 0xe000 | ts_st->pid);
        desc_length_ptr = q;
        q += 2;

        // No optional descriptors

        val = 0xf000 | (q - desc_length_ptr - 2);
        desc_length_ptr[0] = val >> 8;
        desc_length_ptr[1] = val;
    }

    if (err)
        LOGE("The PMT section cannot fit stream %d and all following streams.\n"
             "Try reducing the number of languages in the audio streams "
             "or the total number of streams.", i);

    ts_write_section1(&service->pmt, PMT_TID, service->sid, ts->tables_version, 0, 0,
            data, q - data);
    return 0;
}

int TSMuxer::ts_write_section1(TSSection *s, int tid, int id,
        int version, int sec_num, int last_sec_num,
        uint8_t *buf, int len)
{
    uint8_t section[1024], *q;
    unsigned int tot_len;                
    // Reserved_future_use field must be set to 1 for SDT
    unsigned int flags = tid == SDT_TID ? 0xf000 : 0xb000;

    tot_len = 3 + 5 + len + 4;
    // Check if not too big
    if (tot_len > 1024)
        return -1;

    q    = section;        
    *q++ = tid;
    put16(&q, flags | (len + 5 + 4)); // 5 byte header + 4 byte CRC
    put16(&q, id);         
    *q++ = 0xc1 | (version << 1); // current_next_indicator = 1
    *q++ = sec_num; 
    *q++ = last_sec_num;
    memcpy(q, buf, len);

    ts_write_section(s, section, tot_len);
    return 0;
}

void TSMuxer::ts_write_section(TSSection *s, uint8_t *buf, int len)
{
    unsigned int crc = 0;
    unsigned char packet[TS_PACKET_SIZE];
    const unsigned char *buf_ptr;
    unsigned char *q;
    int first, b, len1, left;

    crc = EHTONL(crc32(crc32table, -1, buf, len - 4));

    buf[len - 4] = (crc >> 24) & 0xff;
    buf[len - 3] = (crc >> 16) & 0xff;
    buf[len - 2] = (crc >>  8) & 0xff;
    buf[len - 1] =  crc        & 0xff;

    // Send each packet
    buf_ptr = buf;
    while (len > 0) {
        first = buf == buf_ptr;
        q     = packet;
        *q++  = 0x47;
        b     = s->pid >> 8;
        if (first)
            b |= 0x40;
        *q++  = b;
        *q++  = s->pid;
        s->cc = (s->cc + 1) & 0xf;
        *q++  = 0x10 | s->cc;
        if (first)
            *q++ = 0; // 0 offset
        len1 = TS_PACKET_SIZE - (q - packet);
        if (len1 > len)
            len1 = len;
        memcpy(q, buf_ptr, len1);
        q += len1;
        // Add known padding data
        left = TS_PACKET_SIZE - (q - packet);
        if (left > 0)
            memset(q, 0xff, left);

        s->write_packet(s, packet);

        buf_ptr += len1;
        len     -= len1;
    }
}

void TSMuxer::section_write_packet(TSSection *s, const uint8_t *packet)
{
    FormatContext *ctx = (FormatContext *) s->opaque;
    ts_prefix_m2ts_header(ctx);
    ctx->file->write_buffer(packet, TS_PACKET_SIZE);
}

void TSMuxer::ts_write_flush(FormatContext *s)
{   
    // Flush current packets
    for (unsigned i = 0; i < s->nb_streams; i++) {
        Stream *st = s->streams[i];
        TSWriteStream *ts_st = (TSWriteStream *) st->priv_data;
        if (ts_st->payload_size > 0) {
            ts_write_pes(s, st, ts_st->payload, ts_st->payload_size,
                    ts_st->payload_pts, ts_st->payload_dts,
                    ts_st->payload_flags & AV_PKT_FLAG_KEY);
            ts_st->payload_size = 0;
        }
    }
}

int TSMuxer::ts_write_packet(FormatContext *s, Packet *pkt)
{
    if (!pkt) {
        ts_write_flush(s);
        return 1;
    } else {
        return ts_write_packet_internal(s, pkt);
    }
}

off_t TSMuxer::size() const
{
    if (m_file)
        return m_file->size();
    else
        return -1;
}

OutputFormat TSMuxer::ts_muxer = { "ts", sizeof(TSWrite), ts_write_packet };

}
