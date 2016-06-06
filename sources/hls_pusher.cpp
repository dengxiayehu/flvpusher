#include <memory>
#include <algorithm>
#include <xlog.h>
#include <xcurl.h>
#include <xfile.h>

#include "config.h"
#include "hls_common.h"
#include "hls_pusher.h"

using namespace xconfig;
using namespace xcurl;
using namespace xfile;
using namespace xutil;
using namespace std;

namespace flvpusher {

HLSPusher::segment::segment(const int duration, const char *uri)
{
    this->duration = duration;
    size = 0;
    sequence = 0;
    url = strdup(uri);
    key_loaded = false;
    key_path = NULL;
    iobuf = NULL;
}

HLSPusher::segment::segment(const segment &obj)
{
    duration = obj.duration;
    size = obj.size;
    sequence = obj.sequence;
    url = strdup(obj.url);
    key_loaded = obj.key_loaded;
    if (key_loaded) {
        memcpy(aes_key, obj.aes_key, AES_SIZE);
    }
    key_path = strdup_(obj.key_path);
    iobuf = NULL;
    lpath = obj.lpath;
}

HLSPusher::segment::~segment()
{
    SAFE_FREE(url);
    SAFE_FREE(key_path);
    SAFE_DELETE(iobuf);
}

bool HLSPusher::segment::operator==(const segment &rhs) const
{
    return sequence == rhs.sequence;
}

string HLSPusher::segment::to_string() const
{
    return sprintf_("segment -- sequence=%d, duration=%d, size=%llu, url=%s, key_path=%s",
                    sequence, duration, (long long unsigned) size, url, key_path);
}

HLSPusher::hls_stream::hls_stream(int id, uint64_t bw, const char *url)
{
    this->id = id;
    bandwidth = bw;
    duration = -1;
    max_segment_length = -1;
    size = 0;
    sequence = 0;
    version = 1;
    cache = true;
    this->url = strdup_(url);
    current_key_path = NULL;
    memset(AES_IV, 0, AES_SIZE);
    iv_loaded = false;
    pl_segment = 0;
}

HLSPusher::hls_stream::hls_stream(const hls_stream &rhs)
{
    id = rhs.id;
    bandwidth = rhs.bandwidth;
    duration = rhs.duration;
    max_segment_length = rhs.max_segment_length;
    size = rhs.size;
    sequence = rhs.sequence;
    version = rhs.version;
    cache = rhs.cache;
    current_key_path = strdup_(rhs.current_key_path);
    url = strdup_(rhs.url);
    memset(AES_IV, 0, AES_SIZE);
    iv_loaded = false;
    pl_segment = 0;
}

HLSPusher::hls_stream::~hls_stream()
{
    for (int n = 0; n < get_segment_count(); ++n) {
        segment *seg = get_segment(n);
        SAFE_DELETE(seg);
    }
    SAFE_FREE(url);
    SAFE_FREE(current_key_path);
}

void HLSPusher::hls_stream::update_stream_size()
{
    size = 0;

    if (!bandwidth)
        return;

    FOR_VECTOR_ITERATOR(segment *, segments, it) {
        size += (*it)->duration * (bandwidth / 8);
    }
}

HLSPusher::segment *HLSPusher::hls_stream::get_segment(int wanted)
{
    int count = segments.size();
    if (count <= 0)
        return NULL;
    if ((wanted < 0) || (wanted >= count))
        return NULL;
    return segments[wanted];
}

int HLSPusher::hls_stream::get_segment_count() const
{
    return segments.size();
}

HLSPusher::segment *HLSPusher::hls_stream::find_segment(const int sequence)
{
    int count = get_segment_count();
    if (count <= 0) return NULL;
    for (int n = 0; n < count; ++n) {
        segment *seg = get_segment(n);
        if (!seg) break;
        if (seg->sequence == sequence)
            return seg;
    }
    return NULL;
}

bool HLSPusher::hls_stream::operator<(const hls_stream &rhs) const
{
    return bandwidth < rhs.bandwidth;
}

bool HLSPusher::hls_stream::operator==(const hls_stream &rhs) const
{
    return id == rhs.id && ((bandwidth == rhs.bandwidth) || (rhs.bandwidth == 0));
}

int HLSPusher::hls_stream::manage_segment_keys(stream_sys *sys)
{
    segment *seg = NULL;
    segment *prev_seg;
    int count = get_segment_count();

    for (int i = 0; i < count; ++i) {
        prev_seg = seg;
        seg = get_segment(i);
        if (!seg)
            continue;
        if (!seg->key_path)
            continue;
        if (seg->key_loaded)
            continue;

        if (prev_seg && prev_seg->key_loaded && !strcmp(seg->key_path, prev_seg->key_path)) {
            memcpy(seg->aes_key, prev_seg->aes_key, AES_SIZE);
            seg->key_loaded = true;
            continue;
        }
        if (download_segment_key(sys, seg) < 0)
            return -1;
        seg->key_loaded = true;
    }
    return 0;
}

int HLSPusher::hls_stream::decode_segment_data(stream_sys *sys, segment *seg)
{
    if (!seg->key_path)
        return 0;

    LOGW("decode_segment_data() not fully implemented");
    return -1;
}

int HLSPusher::hls_stream::download_segment_key(stream_sys *sys, segment *seg)
{
    int curl_hls_timeout = DEFAULT_CURL_HLS_TIMEOUT;
    bool curl_verbose = false;
    if (sys->conf) {
        GET_CONFIG_INT(sys->conf, curl_hls_timeout);
        GET_CONFIG_BOOL(sys->conf, curl_verbose);
    }
    auto_ptr<IOBuffer> iobuf(new IOBuffer);
    if (read_content_from_url(curl_hls_timeout, curl_verbose, true,
                              seg->key_path, iobuf.get()) < 0) {
        LOGE("Failed to load the AES key for segment sequence %d", seg->sequence);
        return -1;
    }

    int len = GETAVAILABLEBYTESCOUNT(*iobuf);
    if (len != AES_SIZE) {
        LOGE("The AES key loaded doesn't have the right size (%d)", len);
        return -1;
    }
    memcpy(seg->aes_key, GETIBPOINTER(*iobuf), sizeof(seg->aes_key));
    return 0;
}

int HLSPusher::hls_stream::download_segment_data(stream_sys *sys, segment *seg, int *cur_stream)
{
    assert(seg);

    uint64_t duration_ = 0;
    string segment_path;

    BEGIN
    AutoLock _l(seg->mutex);

    if (!seg->lpath.empty() || (seg->iobuf && seg->size))
        return 0;

    char *tmp_encoded = (char *) base64_encode(seg->url, strlen(seg->url));
    segment_path = sprintf_("%s%c%s", STR(sys->dir), DIRSEP, tmp_encoded);
    SAFE_FREE(tmp_encoded);

    if (sys->bandwidth > 0 && bandwidth > 0) {
        uint64_t size = (seg->duration * bandwidth);
        int estimated = (int)(size / sys->bandwidth);
        if (estimated > seg->duration) {
            LOGW("Downloading segment %d predicted to take %ds, which exceeds its length (%ds)",
                 seg->sequence, estimated, seg->duration);
        }
    }

    uint64_t start = get_time_now();
    if (download(sys, seg) < 0) {
        LOGE("Downloading segment %d from stream %d failed",
             seg->sequence, *cur_stream);
        return -1;
    }
    duration_ = get_time_now() - start;

    File::flush_content(segment_path,
                        GETIBPOINTER(*seg->iobuf), GETAVAILABLEBYTESCOUNT(*seg->iobuf), "wb");
    seg->lpath = segment_path;
    SAFE_DELETE(seg->iobuf);

    LOGD("Downloaded segment(%s) from stream %d",
         STR(seg->to_string()), *cur_stream);

    if (decode_segment_data(sys, seg) < 0)
        return -1;

    if (bandwidth == 0 && seg->duration > 0)
        bandwidth = (uint64_t)(((double)seg->size * 8) / ((double)seg->duration));
    END

    if (duration_)
        sys->bandwidth = seg->size * 8 * 1000 / MAX((uint64_t) 1, duration_);
    return 0;
}

int HLSPusher::hls_stream::download(stream_sys *sys, segment *seg)
{
    assert(seg);

    if (!seg->iobuf || !seg->size) {
        seg->iobuf = new IOBuffer;

        int curl_hls_timeout = DEFAULT_CURL_HLS_TIMEOUT;
        bool curl_verbose = false;
        if (sys->conf) {
            GET_CONFIG_INT(sys->conf, curl_hls_timeout);
            GET_CONFIG_BOOL(sys->conf, curl_verbose);
        }
        if (read_content_from_url(curl_hls_timeout, curl_verbose, true,
                                  seg->url, seg->iobuf) < 0) {
            SAFE_DELETE(seg->iobuf);
            return -1;
        }
        seg->size = GETAVAILABLEBYTESCOUNT(*seg->iobuf);
    }
    return 0;
}

string HLSPusher::hls_stream::to_string() const
{
    return sprintf_("hls_stream -- id=%d, version=%d, sequence=%d, duration=%d, max_segment_length=%d, bandwidth=%llu, size=%llu, %d# segments, url=%s, cache=%s, current_key_path=%s",
                    id, version, sequence, duration, max_segment_length, (long long unsigned) bandwidth, (long long unsigned) size, segments.size(), url, cache ? "true" : "false", current_key_path);
}

HLSPusher::stream_sys::stream_sys(HLSPusher *pusher_) :
    conf(pusher_->m_conf), m3u8(strdup_(STR(pusher_->m_input))),
    bandwidth(0),
    cache(false), meta(false), live(true), aesmsg(false),
    reload_thrd(NULL), thrd(NULL),
    pusher(pusher_)
{
    char tempdir[] = "flvpusher-XXXXXX";
    mkdtemp(tempdir);
    dir = tempdir;

    memset(&playback, 0, sizeof(playback));
    memset(&playlist, 0, sizeof(playlist));
}

HLSPusher::stream_sys::~stream_sys()
{
    BEGIN
    AutoLock _l(download.mutex);
    download.segment = playback.segment = 0;
    download.wait.signal();
    END

    if (live) {
        JOIN_DELETE_THREAD(reload_thrd);
    }
    JOIN_DELETE_THREAD(thrd);

    for (int i = 0; i < get_hls_count(); ++i) {
        hls_stream *hls = get_hls(i);
        SAFE_DELETE(hls);
    }

    SAFE_FREE(m3u8);

    rmdir_(dir);
}

HLSPusher::hls_stream *HLSPusher::stream_sys::get_hls(int wanted)
{
    int count = streams.size();
    if (count <= 0)
        return NULL;
    if ((wanted < 0) || (wanted >= count))
        return NULL;
    return streams[wanted];
}

int HLSPusher::stream_sys::get_hls_count() const
{
    return streams.size();
}

void HLSPusher::stream_sys::start_reload_thread()
{
    reload_thrd = CREATE_THREAD_ROUTINE(hls_reload_routine, NULL, false);
}

void HLSPusher::stream_sys::start_thread()
{
    thrd = CREATE_THREAD_ROUTINE(hls_routine, NULL, false);
}

int HLSPusher::stream_sys::reload_playlist()
{
    bool stream_appended = false;

    vector<hls_stream *> hls_streams;

    LOGD("Reloading HLS live meta playlist(%s)", STR(pusher->m_input));

    if (get_http_live_meta_playlist(hls_streams) < 0) {
        for (unsigned i = 0; i < hls_streams.size(); ++i)
            SAFE_DELETE(hls_streams[i]);
        hls_streams.clear();

        LOGE("Reloading playlist failed");
        return -1;
    }

    int count = hls_streams.size();
    for (int n = 0; n < count; ++n) {
        hls_stream *hls_new = hls_streams[n];
        if (!hls_new) continue;

        hls_stream *hls_old = find_hls(hls_new);
        if (!hls_old) {
            streams.push_back(hls_new);
            LOGD("New HLS stream appended (id=%d, bandwidth=%llu ignored)",
                 hls_new->id, (long long unsigned) hls_new->bandwidth);
            continue;
        } else if (update_playlist(hls_new, hls_old, &stream_appended) < 0)
            LOGW("Failed updating HLS stream (id=%d, bandwidth=%llu)",
                 hls_new->id, (long long unsigned) hls_new->bandwidth);
        SAFE_DELETE(hls_new);
    }
    hls_streams.clear();

    if (stream_appended) {
        AutoLock _l(download.mutex);
        download.wait.signal();
        return 0;
    }
    return -1;
}

int HLSPusher::stream_sys::get_http_live_meta_playlist(vector<hls_stream *> &streams)
{
    int err = -1;

    for (int i = 0; i < get_hls_count(); ++i) {
        hls_stream *src, *dst;
        src = get_hls(i);
        if (!src) {
            LOGE("get_hls(%d) failed", i);
            return -1;
        }

        dst = new hls_stream(*src);
        streams.push_back(dst);

        auto_ptr<IOBuffer> iobuf(new IOBuffer);
        if (read_m3u8_from_url(this, dst->url, iobuf.get()) < 0)
            err = -1;
        else {
            iobuf->read_from_byte(0);
            err = parse_m3u8(this, streams,
                             GETIBPOINTER(*iobuf), GETAVAILABLEBYTESCOUNT(*iobuf));
        }
    }
    return err;
}

int HLSPusher::stream_sys::update_playlist(hls_stream *hls_new, hls_stream *hls_old, bool *stream_appended)
{
    int count = hls_new->get_segment_count();

    LOGD("Updating hls stream (program-id=%d, bandwidth=%llu) has %d segments",
         hls_new->id, (long long unsigned) hls_new->bandwidth, count);

    bool pl_located = false;
    AutoLock _l(hls_old->mutex);
    hls_old->max_segment_length = -1;
    for (int n = 0; n < count; ++n) {
        segment *p = hls_new->get_segment(n);
        if (!p) continue;

        segment *seg = hls_old->find_segment(p->sequence);
        if (seg) {
            AutoLock _l(seg->mutex);

            assert(p->url);
            assert(seg->url);

            if (!pl_located) {
                for (unsigned i = hls_old->pl_segment;
                     i < hls_old->segments.size();
                     ++i) {
                    if (hls_old->get_segment(i)->sequence == p->sequence) {
                        hls_old->pl_segment = i;
                        break;
                    }
                }
                pl_located = true;
            }

            if ((p->sequence != seg->sequence) ||
                (p->duration != seg->duration) ||
                (strcmp(p->url, seg->url))) {
                LOGW("Existing segment found with different content - resetting");
                LOGW("- sequence: new=%d, old=%d", p->sequence, seg->sequence);
                LOGW("- duration: new=%d, old=%d", p->duration, seg->duration);
                LOGW("- file: new=%s", p->url);
                LOGW("        old=%s", seg->url);

                seg->sequence = p->sequence;
                seg->duration = p->duration;
                SAFE_FREE(seg->url);
                seg->url = strdup(p->url);

                if ((p->key_path || p->key_loaded) &&
                    seg->iobuf)
                    SAFE_DELETE(seg->iobuf);
                SAFE_FREE(seg->key_path);
                seg->key_path = strdup_(p->key_path);
            }
            SAFE_DELETE(p);
        } else {
            int last = hls_old->get_segment_count() - 1;
            segment *l = hls_old->get_segment(last);
            if (!l) {
                SAFE_DELETE(p);
                continue;
            }

            if (!pl_located) {
                hls_old->pl_segment = hls_old->segments.size();
                pl_located = true;
            }

            if (l->sequence + 1 != p->sequence) {
                LOGW("Gap in sequence numbers found: new=%d expected %d",
                     p->sequence, l->sequence+1);
            }
            hls_old->segments.push_back(p);
            LOGD("- segment %d appended <%d# in total>", p->sequence, hls_old->get_segment_count());
            hls_old->max_segment_length = MAX(hls_old->max_segment_length, p->duration);
            LOGD("  - segments new max duration %d", hls_old->max_segment_length);

            *stream_appended = true;
        }
    }

    if (pl_located && hls_old->pl_segment)
        --hls_old->pl_segment;
    hls_old->sequence = hls_new->sequence;
    hls_old->duration = (hls_new->duration == -1) ? hls_old->duration : hls_new->duration;
    hls_old->cache = hls_new->cache;
    hls_new->segments.clear();
    return 0;
}

HLSPusher::hls_stream *HLSPusher::stream_sys::find_hls(hls_stream *hls_new)
{
    int count = get_hls_count();
    for (int n = 0; n < count; ++n) {
        hls_stream *hls = get_hls(n);
        if (hls) {
            if ((hls->id == hls_new->id) &&
                ((hls->bandwidth == hls_new->bandwidth) || (hls_new->bandwidth==0)) &&
                (!strcmp(hls->url, hls_new->url)))
                return hls;
        }
    }
    return NULL;
}

HLSPusher::HLSPusher(const string &input, RtmpHandler *&rtmp_hdl, Config *conf) :
    MediaPusher(input, rtmp_hdl),
    m_conf(conf), m_sys(NULL)
{
}

HLSPusher::~HLSPusher()
{
    SAFE_DELETE(m_sys);
}

bool HLSPusher::compare_streams(const void *a, const void *b)
{
    hls_stream *stream_a = (hls_stream *) a;
    hls_stream *stream_b = (hls_stream *) b;

    return stream_a->bandwidth < stream_b->bandwidth;
}

int HLSPusher::prepare()
{
    m_sys = new stream_sys(this);

    auto_ptr<IOBuffer> iobuf(new IOBuffer);
    if (read_m3u8_from_url(m_sys, STR(m_input), iobuf.get()) < 0) {
        LOGE("read_m3u8_from_url(%s) failed", STR(m_input));
        return -1;
    }

    if (!is_valid_m3u8(GETIBPOINTER(*iobuf), GETAVAILABLEBYTESCOUNT(*iobuf))) {
        LOGE("Validate url \"%s\"'s content failed", STR(m_input));
        return -1;
    }

    iobuf->read_from_byte(0); // Add trailing '\0'
    if (parse_m3u8(m_sys, m_sys->streams,
                   GETIBPOINTER(*iobuf), GETAVAILABLEBYTESCOUNT(*iobuf)) < 0) {
        LOGE("parse_m3u8(%s) failed", STR(m_input));
        return -1;
    }

    sort(m_sys->streams.begin(), m_sys->streams.end(), compare_streams);

    int current = m_sys->playback.stream = m_sys->get_hls_count() - 1;
    m_sys->playback.segment = m_sys->download.segment = choose_segment(m_sys, current);

    m_sys->streams[current]->manage_segment_keys(m_sys);

    if (prefetch(m_sys, &current) < 0) {
        LOGE("Prefetching segment(s) failed");
        return -1;
    }

    m_sys->download.stream = current;
    m_sys->playback.stream = current;

    hls_stream *hls = m_sys->get_hls(current);
    hls->pl_segment = m_sys->playback.segment;
    if (m_sys->live) {
        m_sys->playlist.last = get_time_now();
        m_sys->playlist.wakeup = m_sys->playlist.last + hls->duration*1000;
        m_sys->start_reload_thread();
    }

    m_sys->start_thread();
    return 0;
}

int HLSPusher::loop()
{
    if (prepare() < 0) {
        LOGE("HLSPusher's prepare() failed");
        return -1;
    }
    
    LOGI("Pushing hls \"%s\" ..", STR(m_input));

    while (!m_quit) {
        // TODO
        sleep_(100);
    }
    return 0;
}

int HLSPusher::read_content_from_url(int timeout, bool verbose, bool trace_ascii,
                                     const char *url, IOBuffer *iobuf)
{
    auto_ptr<Curl> curl(new Curl);
    Curl::request *req =
        Curl::request::build(Curl::GET, url, Curl::write_cb, iobuf, timeout, NULL,
                             verbose, trace_ascii, true, true);
    if (!req) {
        LOGE("Build GET for url \"%s\" failed", url);
        return -1;
    }
    if (curl->perform(req, NULL) < 0 ||
        req->response_code != 200) {
        LOGE("read_content_from_url(%s) failed (response_code=%d)",
             url, req->response_code);
        Curl::request::recycle(&req);
        return -1;
    }
    Curl::request::recycle(&req);
    return 0;
}

int HLSPusher::read_m3u8_from_url(stream_sys *sys, const char *url, IOBuffer *iobuf)
{
    int curl_hls_timeout = DEFAULT_CURL_HLS_TIMEOUT;
    bool curl_verbose = true, curl_trace_ascii = false;
    if (sys->conf) {
        GET_CONFIG_INT(sys->conf, curl_hls_timeout);
        GET_CONFIG_BOOL(sys->conf, curl_verbose);
        GET_CONFIG_BOOL(sys->conf, curl_trace_ascii);
    }
    return read_content_from_url(curl_hls_timeout, curl_verbose, curl_trace_ascii,
                                 url, iobuf);
}

int HLSPusher::parse_m3u8(stream_sys *sys, vector<hls_stream *> &streams,
                          uint8_t *buffer, const ssize_t len)
{
    assert(sys && buffer);

    uint8_t *read, *begin = buffer, *end = buffer + len;
    char *line = read_line(begin, &read, end - begin);
    if (!line) return -1;
    begin = read;

    if (strncmp(line, "#EXTM3U", 7)) {
        LOGE("Missing #EXTM3U tag .. aborting");
        SAFE_FREE(line);
        return -1;
    }

    SAFE_FREE(line);

    int version = 1;
    uint8_t *p = (uint8_t *) strstr((const char *) buffer, "#EXT-X-VERSION:");
    if (p) {
        uint8_t *tmp = NULL;
        char *verstr = read_line(p, &tmp, end - p);
        if (!verstr) return -1;
        int ret = sscanf((const char*) verstr, "#EXT-X-VERSION:%d", &version);
        if (ret != 1) {
            LOGW("#EXT-X-VERSION: no protocol version found, assuming version 1.");
            version = 1;
        }
        SAFE_FREE(verstr);
    }

    sys->live = (strstr((const char *) buffer, "#EXT-X-ENDLIST") == NULL) ? true : false;

    bool meta = (strstr((const char *) buffer, "#EXT-X-STREAM-INF") == NULL) ? false : true;

    int err = 0;

    if (meta) {
        LOGD("Meta playlist");
        do {
            line = read_line(begin, &read, end - begin);
            if (!line) break;
            begin = read;

            if (!strncmp(line, "#EXT-X-STREAM-INF", 17)) {
                sys->meta = true;
                char *uri = read_line(begin, &read, end - begin);
                if (!uri) err = -1;
                else {
                    if (*uri == '#') {
                        LOGW("Skipping invalid stream-inf: %s", uri);
                        SAFE_FREE(uri);
                    } else {
                        bool new_stream_added = false;
                        hls_stream *hls = NULL;
                        err = parse_stream_information(sys, streams, &hls, line, uri);
                        if (!err) {
                            new_stream_added = true;
                        }

                        SAFE_FREE(uri);

                        if (hls) {
                            auto_ptr<IOBuffer> iobuf(new IOBuffer);
                            if (read_m3u8_from_url(sys, hls->url, iobuf.get()) < 0) {
                                LOGE("Failed to read \"%s\", continue for other streams", hls->url);

                                if (new_stream_added) {
                                    streams.pop_back();
                                    SAFE_DELETE(hls);
                                }

                                err = 0;
                            } else {
                                iobuf->read_from_byte(0);
                                err = parse_m3u8(sys, streams,
                                                 GETIBPOINTER(*iobuf), GETAVAILABLEBYTESCOUNT(*iobuf));
                            }

                            if (hls) {
                                hls->version = version;
                                if (!sys->live) {
                                    hls->update_stream_size();
                                }
                            }
                        }
                    }
                }

                begin = read;
            }

            SAFE_FREE(line);

            if (begin >= end)
                break;
        } while (err == 0);

        size_t stream_count = streams.size();
        if (stream_count) {
            LOGD("%d streams loaded in Meta playlist", stream_count);
        } else {
            LOGE("No playable streams found in Meta playlist");
            err = -1;
        }
    } else {
        LOGD("%s Playlist HLS protocol version: %d", sys->live ? "Live" : "VOD", version);

        hls_stream *hls = NULL;
        if (sys->meta)
            hls = streams.back();
        else {
            hls = new hls_stream(0, 0, sys->m3u8);
            streams.push_back(hls);
            if (hls) {
                p = (uint8_t *)strstr((const char *)buffer, "#EXT-X-TARGETDURATION:");
                if (p) {
                    uint8_t *rest = NULL;
                    char *duration = read_line(p, &rest,  end - p);
                    if (!duration) return -1;
                    err = parse_target_duration(sys, hls, duration);
                    SAFE_FREE(duration);
                    p = NULL;
                }

                hls->version = version;
            }
            else return -1;
        }
        assert(hls);

        bool media_sequence_loaded = false;
        int segment_duration = -1;
        do {
            line = read_line(begin, &read, end - begin);
            if (!line) break;
            begin = read;

            if (!strncmp(line, "#EXTINF", 7))
                err = parse_segment_information(hls, line, &segment_duration);
            else if (!strncmp(line, "#EXT-X-TARGETDURATION", 21))
                err = parse_target_duration(sys, hls, line);
            else if (!strncmp(line, "#EXT-X-MEDIA-SEQUENCE", 21)) {
                if (!media_sequence_loaded) {
                    err = parse_media_sequence(sys, hls, line);
                    media_sequence_loaded = true;
                }
            } else if (!strncmp(line, "#EXT-X-KEY", 10))
                err = parse_key(sys, hls, line);
            else if (!strncmp(line, "#EXT-X-PROGRAM-DATE-TIME", 24))
                err = parse_program_date_time(sys, hls, line);
            else if (!strncmp(line, "#EXT-X-ALLOW-CACHE", 18))
                err = parse_allow_cache(sys, hls, line);
            else if (!strncmp(line, "#EXT-X-DISCONTINUITY", 20))
                err = parse_discontinuity(sys, hls, line);
            else if (!strncmp(line, "#EXT-X-VERSION", 14))
                err = parse_version(sys, hls, line);
            else if (!strncmp(line, "#EXT-X-ENDLIST", 14))
                err = parse_end_list(sys, hls);
            else if (strncmp(line, "#", 1) && (*line != '\0') ) {
                err = parse_add_segment(hls, segment_duration, line);
                segment_duration = -1;
            }

            SAFE_FREE(line);

            if (begin >= end)
                break;
        } while (err == 0);

        SAFE_FREE(line);
    }

    return err;
}

int HLSPusher::parse_stream_information(stream_sys *sys, vector<hls_stream *> &streams,
                                        hls_stream **hls, char *read, const char *uri)
{
    int id;
    uint64_t bw;
    char *attr;

    assert(*hls == NULL);

    attr = parse_attributes(read, "PROGRAM-ID");
    if (attr) {
        id = atol(attr);
        SAFE_FREE(attr);
    } else id = 0;

    attr = parse_attributes(read, "BANDWIDTH");
    if (!attr) {
        LOGE("#EXT-X-STREAM-INF: expected BANDWIDTH=<value>");
        return -1;
    }
    bw = atol(attr);
    SAFE_FREE(attr);

    if (!bw) {
        LOGE("#EXT-X-STREAM-INF: bandwidth cannot be 0");
        return -1;
    }

    LOGD("Bandwidth adaptation detected (program-id=%d, bandwidth=%llu).",
         id, (unsigned long long) bw);

    char *r_uri = relative_uri(sys->m3u8, uri);

    *hls = new hls_stream(id, bw, r_uri ? r_uri : uri);
    streams.push_back(*hls);

    SAFE_FREE(r_uri);
    return *hls ? 0 : -1;
}

char *HLSPusher::parse_attributes(const char *line, const char *attr)
{
    char *p;
    char *begin = (char *) line;
    char *end = begin + strlen(line);

    if (!(p = strchr(begin, ':' )))
        return NULL;

    begin = p;
    do {
        if (!strncasecmp(begin, attr, strlen(attr)) &&
            begin[strlen(attr)] == '=') {
            p = strchr(begin, ',');
            begin += strlen(attr) + 1;

            if( begin[0] == '"' ) {
                char *valueend = strchr(begin+1, '"');

                if(!valueend)
                    return NULL;

                p = strchr(valueend, ',');
            }
            if (begin >= end)
                return NULL;
            if (!p)
                return strndup(begin, end - begin);
            return strndup(begin, p - begin);
        }
        begin++;
    } while(begin < end);

    return NULL;
}

int HLSPusher::parse_target_duration(stream_sys *sys, hls_stream *hls, char *read)
{
    assert(hls);

    int duration = -1;
    int ret = sscanf(read, "#EXT-X-TARGETDURATION:%d", &duration);
    if (ret != 1) {
        LOGE("expected #EXT-X-TARGETDURATION:<s>");
        return -1;
    }

    hls->duration = duration;
    return 0;
}

int HLSPusher::parse_segment_information(hls_stream *hls, char *read, int *duration)
{
    assert(hls && read);

    char *next = NULL;
    char *token = strtok_r(read, ":", &next);
    if (!token) return -1;

    token = strtok_r(NULL, ",", &next);
    if (!token) return -1;

    int value;
    char *endptr;
    errno = 0;
    if (hls->version < 3) {
        value = strtol(token, &endptr, 10);
        if (token == endptr || errno == ERANGE) {
            *duration = -1;
            return -1;
        }
        *duration = value;
    } else {
        double d = strtod(token, &endptr);
        if (token == endptr || errno == ERANGE) {
            *duration = -1;
            return -1;
        }
        if ((d) - ((int)d) >= 0.5)
            value = ((int)d) + 1;
        else
            value = ((int)d);
        *duration = value;
    }
    if( *duration > hls->max_segment_length)
        hls->max_segment_length = *duration;

    return 0;
}

int HLSPusher::parse_media_sequence(stream_sys *sys, hls_stream *hls, char *read)
{
    assert(hls);

    int sequence;
    int ret = sscanf(read, "#EXT-X-MEDIA-SEQUENCE:%d", &sequence);
    if (ret != 1) {
        LOGE("expected #EXT-X-MEDIA-SEQUENCE:<s>");
        return -1;
    }

    if (hls->sequence > 0) {
        if (sys->live) {
            hls_stream *last = sys->streams.back();
            segment *last_segment = last->get_segment(last->get_segment_count()-1);
            if ((last_segment->sequence < sequence) &&
                (sequence - last_segment->sequence > 1)) {
                LOGE("EXT-X-MEDIA-SEQUENCE gap in playlist (new=%d, old=%d)",
                     sequence, last_segment->sequence);
            }
        } else {
            LOGE("EXT-X-MEDIA-SEQUENCE already present in playlist (new=%d, old=%d)",
                 sequence, hls->sequence);
        }
    }
    hls->sequence = sequence;
    return 0;
}

int HLSPusher::parse_key(stream_sys *sys, hls_stream *hls, char *read)
{
    assert(hls);

    int err = 0;
    char *attr = parse_attributes(read, "METHOD");
    if (!attr) {
        LOGE("#EXT-X-KEY: expected METHOD=<value>");
        return err;
    }

    if (!strncasecmp(attr, "NONE", 4)) {
        char *uri = parse_attributes(read, "URI");
        if (!uri) {
            LOGE("#EXT-X-KEY: URI not expected");
            err = -1;
        }
        SAFE_FREE(uri);
        if (hls->version >= 2) {
            char *iv = parse_attributes(read, "IV");
            if (!iv) {
                LOGE("#EXT-X-KEY: IV not expected");
                err = -1;
            }
            SAFE_FREE(iv);
        }
    } else if (!strncasecmp(attr, "AES-128", 7)) {
        char *value, *uri, *iv;
        if (!sys->aesmsg) {
            LOGD("playback of AES-128 encrypted HTTP Live media detected.");
            sys->aesmsg = true;
        }
        value = uri = parse_attributes(read, "URI");
        if (!value)
        {
            LOGE("#EXT-X-KEY: URI not found for encrypted HTTP Live media in AES-128");
            SAFE_FREE(attr);
            return -1;
        }

        if (*value == '"') {
            uri = value + 1;
            char* end = strchr(uri, '"');
            if (end != NULL)
                *end = 0;
        }

        if(strstr( uri , "://" ) ) {
            hls->current_key_path = strdup(uri);
        } else {
            hls->current_key_path = relative_uri(hls->url, uri);
        }
        SAFE_FREE(value);

        value = iv = parse_attributes(read, "IV");
        if (!iv) {
            hls->iv_loaded = false;
        } else {
            if (string_to_iv(iv, hls->AES_IV) < 0) {
                LOGE("IV invalid");
                err = -1;
            } else {
                hls->iv_loaded = true;
            }
            SAFE_FREE(value);
        }
    } else {
        LOGW("playback of encrypted HTTP Live media is not supported.");
        err = -1;
    }
    SAFE_FREE(attr);
    return err;
}

int HLSPusher::parse_program_date_time(stream_sys *sys, hls_stream *hls, char *read)
{
    UNUSED(hls);
    LOGW("tag not supported: #EXT-X-PROGRAM-DATE-TIME %s", read);
    return 0;
}

int HLSPusher::parse_allow_cache(stream_sys *sys, hls_stream *hls, char *read)
{
    assert(hls);

    char answer[4] = "\0";
    int ret = sscanf(read, "#EXT-X-ALLOW-CACHE:%3s", answer);
    if (ret != 1) {
        LOGE("#EXT-X-ALLOW-CACHE, ignoring ...");
        return -1;
    }

    hls->cache = (strncmp(answer, "NO", 2) != 0);
    return 0;
}

int HLSPusher::parse_discontinuity(stream_sys *sys, hls_stream *hls, char *read)
{
    assert(hls);

    LOGW("#EXT-X-DISCONTINUITY %s", read);
    return 0;
}

int HLSPusher::parse_version(stream_sys *sys, hls_stream *hls, char *read)
{
    assert(hls);

    int version;
    int ret = sscanf(read, "#EXT-X-VERSION:%d", &version);
    if (ret != 1) {
        LOGE("#EXT-X-VERSION: no protocol version found, should be version 1.");
        return -1;
    }

    hls->version = version;
    if (hls->version <= 0 || hls->version > 3) {
        LOGE("#EXT-X-VERSION should be version 1, 2 or 3 iso %d", version);
        return -1;
    }
    return 0;
}

int HLSPusher::parse_end_list(stream_sys *sys, hls_stream *hls)
{
    assert(hls);

    sys->live = false;
    LOGD("video on demand (vod) mode");
    return 0;
}

int HLSPusher::parse_add_segment(hls_stream *hls, const int duration, const char *uri)
{
    assert(hls);
    assert(uri);

    AutoLock _l(hls->mutex);

    char *r_uri = relative_uri(hls->url, uri);

    segment *seg = new segment(duration, r_uri ? r_uri : uri);
    hls->segments.push_back(seg);
    seg->key_path = strdup_(hls->current_key_path);
    seg->sequence = hls->sequence + hls->get_segment_count() - 1;
    SAFE_FREE(r_uri);
    return 0;
}

char *HLSPusher::read_line(uint8_t *buffer, uint8_t **pos, const size_t len)
{
    assert(buffer);

    char *line = NULL;
    uint8_t *begin = buffer;
    uint8_t *p = begin;
    uint8_t *end = p + len;

    while (p < end) {
        if ((*p == '\r') || (*p == '\n') || (*p == '\0'))
            break;
        p++;
    }

    line = strndup((char *) begin, p - begin);

    while ((*p == '\r') || (*p == '\n') || (*p == '\0')) {
        if (*p == '\0') {
            *pos = end;
            break;
        } else {
            p++;
            *pos = p;
        }
    }

    return line;
}

char *HLSPusher::relative_uri(const char *url, const char *path)
{
    char *ret = NULL;
    const char *fmt;

    assert(url && path);

    if (!strncmp(path, "http", 4))
        return NULL;

    size_t len = strlen(path);

    char *new_url = strdup(url);

    if (path[0] == '/') {
        char *slash = strchr(&new_url[8], '/');
        if (!slash) goto end;
        *slash = '\0';
        fmt = "%s%s";
    } else {
        int levels = 0;
        while(len >= 3 && !strncmp(path, "../", 3)) {
            path += 3;
            len -= 3;
            levels++;
        }
        do {
            char *slash = strrchr(new_url, '/');
            if (!slash) goto end;
            *slash = '\0';
        } while (levels--);
        fmt = "%s/%s";
    }

    ret = strdup(STR(sprintf_(fmt, new_url, path)));

end:
    SAFE_FREE(new_url);
    return ret;
}

int HLSPusher::string_to_iv(char *string_hexa, uint8_t iv[AES_SIZE])
{
    unsigned long long iv_hi, iv_lo;
    char *end = NULL;
    if (*string_hexa++ != '0')
        return -1;
    if (*string_hexa != 'x' && *string_hexa != 'X')
        return -1;

    string_hexa++;

    size_t len = strlen(string_hexa);
    if (len <= 16) {
        iv_hi = 0;
        iv_lo = strtoull(string_hexa, &end, 16);
        if (*end) return -1;
    } else {
        iv_lo = strtoull(&string_hexa[len-16], &end, 16);
        if (*end) return -1;
        string_hexa[len-16] = '\0';
        iv_hi = strtoull(string_hexa, &end, 16);
        if (*end) return -1;
    }

    for (int i = 7; i >= 0 ; --i) {
        iv[  i] = iv_hi & 0xff;
        iv[8+i] = iv_lo & 0xff;
        iv_hi >>= 8;
        iv_lo >>= 8;
    }

    return 0;
}

int HLSPusher::choose_segment(stream_sys *sys, const int current)
{
    hls_stream *hls = sys->get_hls(current);
    if (!hls) return 0;

    int wanted = 0;
    int duration = 0;
    int sequence = 0;
    int count = hls->get_segment_count();
    int i = sys->live ? count - 1 : -1;

    while ((i >= 0) && (i < count)) {
        segment *seg = hls->get_segment(i);
        assert(seg);

        if (seg->duration > hls->duration) {
            LOGE("EXTINF:%d duration is larger than EXT-X-TARGETDURATION:%d",
                 seg->duration, hls->duration);
        }

        duration += seg->duration;
        if (duration >= 3 * hls->duration) {
            wanted = i;
            sequence = seg->sequence;
            break;
        }

        i--;
    }

    LOGD("Choose segment %d/%d (sequence=%d)", wanted, count, sequence);
    return wanted;
}

int HLSPusher::prefetch(stream_sys *sys, int *current)
{
    int stream = *current;
    hls_stream *hls = sys->get_hls(stream);
    if (!hls) return -1;

    if (!hls->get_segment_count()) {
        return -1;
    } else if (hls->get_segment_count() == 1 && sys->live) {
        LOGW("Only 1 segment available to prefetch in live stream; may stall");
    }

    unsigned segment_amount = (unsigned) (0.5f + 10/hls->duration);
    unsigned segment_count = hls->get_segment_count();
    for (unsigned i = 0; i < MIN(segment_count, segment_amount); i++) {
        segment *seg = hls->get_segment(sys->download.segment);
        if (!seg) return -1;

        if (!seg->lpath.empty() || (seg->iobuf && seg->size)) {
            ++sys->download.segment;
            continue;
        }

        if (hls->download_segment_data(sys, seg, current) < 0)
            return -1;

        ++sys->download.segment;

        if (*current != stream) {
            hls_stream *hls = sys->get_hls(*current);
            if (!hls) return -1;
            stream = *current;
        }
    }

    return 0;
}

void *HLSPusher::stream_sys::hls_reload_routine(void *arg)
{
    LOGD("hls_reload_routine for \"%s\" started", STR(pusher->m_input));

    assert(live);

    double wait = 1.0;
    while (!pusher->m_quit) {
        uint64_t now = get_time_now();
        if (now >= playlist.wakeup) {
            if (reload_playlist() < 0) {
                playlist.tries++;
                if (playlist.tries == 1) wait = 0.5;
                else if (playlist.tries == 2) wait = 1;
                else if (playlist.tries == 3) wait = 1.5;

                if (download.segment - playback.segment < 3) {
                    playlist.tries = 0;
                    wait = 0.5;
                }
            } else {
                playlist.tries = 0;
                wait = 1.0;
            }

            hls_stream *hls = get_hls(download.stream);
            assert(hls);

            playlist.last = now;
            playlist.wakeup = now;
            if (hls->max_segment_length > 0) {
                playlist.wakeup += (uint64_t) (hls->max_segment_length * wait * 1000);
            } else {
                playlist.wakeup += (uint64_t) (hls->duration * wait * 1000);
            }
        }

        short_snap(playlist.wakeup - now, &pusher->m_quit);
    }

    LOGD("hls_reload_routine for \"%s\" ended", STR(pusher->m_input));
    return (void *) NULL;
}

void *HLSPusher::stream_sys::hls_routine(void *arg)
{
    LOGD("hls_routine for \"%s\" started", STR(pusher->m_input));

    while (!pusher->m_quit) {
        hls_stream *hls = get_hls(download.stream);
        assert(hls);

        hls->mutex.lock();
        int count = hls->get_segment_count();
        hls->mutex.unlock();

        if (download.segment >= count) {
            AutoLock _l(download.mutex);
            while (download.segment >= count && !pusher->m_quit) {
                download.wait.wait();
                if (live || pusher->m_quit)
                    break;
            }
        }

        if (pusher->m_quit)
            break;

        hls->mutex.lock();
        segment *seg = hls->get_segment(download.segment);
        hls->mutex.unlock();

        if (seg &&
            hls->download_segment_data(this, seg, &download.stream) < 0) {
            if (pusher->m_quit)
                break;
            // Fall through
        }

        AutoLock _l(download.mutex);
        ++download.segment;
    }

    LOGD("hls_routine for \"%s\" ended", STR(pusher->m_input));
    return (void *) NULL;
}

}
