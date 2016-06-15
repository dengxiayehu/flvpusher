#include "flv_parser.h"

#include <cstdlib>

//#define XDEBUG

using namespace xutil;
using namespace amf;

namespace flvpusher {

FLVParser::FLVParser()
{
}

FLVParser::~FLVParser()
{
    m_file.close();
}

int FLVParser::set_file(const std::string &flv_file)
{
    if (!m_file.open(flv_file, "rb"))
        return -1;

    FLVHeader header;
    if (read_header(header) < 0) {
        LOGE("read_header failed");
        return -1;
    }
    return 0;
}

bool FLVParser::eof() const
{
    return m_file.is_opened() ?
        m_file.eof() || m_file.cursor() >= m_file.size() : true;
}

int FLVParser::read_header(FLVHeader &hdr,
                           uint8_t *buf, uint32_t buf_size) const
{
    if (!buf) {
        if (!m_file.read_buffer(reinterpret_cast<uint8_t *>(&hdr),
                                sizeof(FLVHeader))) {
            LOGE("Read from file \"%s\" failed",
                 m_file.get_path());
            return -1;
        }
    } else {
        memcpy(&hdr, buf, sizeof(FLVHeader));
        buf += sizeof(FLVHeader);
        buf_size -= sizeof(FLVHeader);
    }

    /* Since hdr.dataoffset is in big-endian mode,
     * convert it to little-endian mode */
    hdr.dataoffset = ENTOHL(hdr.dataoffset);

    if (strncmp(reinterpret_cast<char *>(hdr.signature), "FLV", 3)) {
        LOGE("Not a valid flv file");
        return -1;
    }

    if (hdr.version != 1) {
        LOGE("FLV file's version(%d) not supported", hdr.version);
        return -1;
    }

    if (hdr.dataoffset != 9) {
        LOGE("FLV version 1 should have 9 bytes flv_header, not %d bytes",
             hdr.dataoffset);
        return -1;
    }
    
    // Read the "Previous Tag Size"
    uint32_t prev_tag_size = 0;
    if (!buf) {
        if (!m_file.readui32(&prev_tag_size, true)) {
            LOGE("Read \"Prev-Tag-Size\" failed");
            return -1;
        }
    } else {
        prev_tag_size = ENTOHL(*(uint32_t*)buf);
        buf += sizeof(uint32_t);
        buf_size -= sizeof(uint32_t);
    }
    if (prev_tag_size != 0) {
        LOGE("First \"Prev-Tag-Size\" is not zero!");
        return -1;
    }

#ifdef XDEBUG
    LOGD("Signature: FLV");
    LOGD("Version: %d", hdr.version);
    LOGD("Has audio: %s", hdr.audio ? "true" : "false");
    LOGD("Has video: %s", hdr.video ? "true" : "false");
    LOGD("Header length: %d", hdr.dataoffset);
    LOGD("Previous Tag Size: %u", prev_tag_size);
#endif
    return hdr.dataoffset + sizeof(uint32_t);
}

int FLVParser::read_tag(FLVTag *&tag, uint8_t *buf, uint32_t buf_size)
{
    if (!buf) {
        if (!m_file.read_buffer(reinterpret_cast<uint8_t *>(&tag->hdr),
                                sizeof(FLVTagHeader))) {
            LOGE("Read tag header failed");
            return -1;
        }
    } else {
        memcpy(&tag->hdr, buf, sizeof(FLVTagHeader));
        buf += sizeof(FLVTagHeader);
        buf_size -= sizeof(FLVTagHeader);
    }

    /* Convert FLVTagHeader's |datasize|, |timestamp| and |stream_id|
     * from "Network-Order" to "Host-Order" */
    ENDIAN_CHANGE_UI24(tag->hdr.datasize);
    ENDIAN_CHANGE_UI24(tag->hdr.timestamp);
    ENDIAN_CHANGE_UI24(tag->hdr.stream_id);

    size_t len = VALUI24(tag->hdr.datasize);
    byte *strm = NULL;
    int ret = 0;

    if (!buf) {
        strm = (byte *) m_mem_holder.alloc(len);
        if (!m_file.read_buffer(strm, len)) {
            LOGE("Read tag data from file failed");
            return -1;
        }
    } else {
        strm = buf;
        buf += len;
        buf_size -= len;
    }

    switch (tag->hdr.typ) {
    case TAG_AUDIO:
        ret = handle_audio(tag->dat.audio, strm, len);
        break;

    case TAG_VIDEO:
        ret = handle_video(tag->dat.video, strm, len);
        break;

    case TAG_SCRIPT: {
        ret = handle_script(tag->dat.script, strm, len);
#ifdef XDEBUG
        print_amf_list("", &tag->dat.script);
#endif
        } break;

    default:
        LOGE("Not supported tag type %d", tag->hdr.typ);
        return -1;
    }

#ifdef XDEBUG
    LOGD("Tag type: %s", tag->hdr.typ == TAG_AUDIO ?
            "Audio" : (tag->hdr.typ == TAG_VIDEO ? "Video" : "Script"));
    LOGD("Tag datasize: %u", VALUI24(tag->hdr.datasize));
    LOGD("Tag timestamp: %u", VALUI24(tag->hdr.timestamp));
    LOGD("Tag timestamp-extended: %u", tag->hdr.timestamp_ext);
    LOGD("Tag stream-id: %u", VALUI24(tag->hdr.stream_id));
#endif

    // Read the "Previous Tag Size"
    uint32_t prev_tag_size = 0;
    if (!buf) {
        if (!m_file.readui32(&prev_tag_size, true)) {
            LOGE("Read prev_tag_size failed");
            return -1;
        }
    } else {
        prev_tag_size = ENTOHL(*(uint32_t*)buf);
        buf += sizeof(uint32_t);
        buf_size -= sizeof(uint32_t);
    }
       
    if (prev_tag_size !=
            VALUI24(tag->hdr.datasize) + sizeof(FLVTagHeader)) {
        LOGE("Read \"Prev-Tag-Size\" failed, %u != %u + %u",
             prev_tag_size,
             VALUI24(tag->hdr.datasize), sizeof(FLVTagHeader));
        return -1;
    }

    return VALUI24(tag->hdr.datasize) +
        sizeof(FLVTagHeader) + sizeof(uint32_t);
}

int FLVParser::handle_script(AMFData &script,
                             const byte strm[], uint32_t len)
{
    const byte *p = strm;

    INIT_LIST_HEAD(&script);

    /* NOTE: Unmake following lines to force first
     * amf-obj is "onMetaData" string */

#if 0
    // First amf-object need to be "onMetaData" string
    AMF *amfobj = alloc_amf(*p++);
    if (amfobj->typ != AMF_TYPE_STRING ||
        get_amf_string(p, len-(p-strm), amfobj->amfstr) < 0 ||
        strcasecmp(amfobj->amfstr.str, "onMetaData")) {
        LOGE("First amf-object need to be \"onMetaData\" string");
        free_amf(amfobj);
        return -1;
    }

    // Link this amfobj to script
    list_add_tail(&amfobj->list, &script);
#endif

    // Parse next amfobs and link them to script
    while (len-(p-strm) > 0) {
        // NOTE: p is a reference, which is updated automatically
        if (parse_amf(p, len-(p-strm), &script) < 0) {
            LOGE("parse_amf failed");
            return -1;
        }
    }
    return 0;
}

int FLVParser::parse_avc(const byte *&p, uint32_t len,
                         FLVVideoTagData &vdat)
{
    const byte *savep = p;

    vdat.pkt.pkt_typ = *p++;
    INITUI24(vdat.pkt.compostion_time, ENTOH24(p));
    p += sizeof(uint24_t);

    if (vdat.pkt.pkt_typ != NALU &&
        VALUI24(vdat.pkt.compostion_time) != 0) {
        LOGE("AVCPktType %u should with 0 compostion_time, not %u",
             vdat.pkt.pkt_typ, VALUI24(vdat.pkt.compostion_time));
        return -1;
    }

    switch (vdat.pkt.pkt_typ) {
    case SEQUENCE_HEADER: {
        AVCDecorderConfigurationRecord &avc_dcr = vdat.pkt.avc_dcr;
        avc_dcr.version = *p++;
        avc_dcr.profile = *p++;
        avc_dcr.profile_compatibility = *p++;
        avc_dcr.level = *p++;
        *(uint8_t*)(&avc_dcr.level + 1) = *p++;
        *(uint8_t*)(&avc_dcr.level + 2) = *p++;
        avc_dcr.sps_length = ENTOHS(*(uint16_t *)p);
        p += sizeof(uint16_t);
        avc_dcr.sps = new byte[avc_dcr.sps_length];
        memcpy(avc_dcr.sps, p, avc_dcr.sps_length);
        p += avc_dcr.sps_length;
        avc_dcr.num_of_pps = *p++;
        avc_dcr.pps_length = ENTOHS(*(uint16_t *)p);
        p += sizeof(uint16_t);
        avc_dcr.pps = new byte[avc_dcr.pps_length];
        memcpy(avc_dcr.pps, p, avc_dcr.pps_length);
        p += avc_dcr.pps_length;
#ifdef XDEBUG
        print_avc_dcr(avc_dcr);
#endif
        } break;

    case NALU: {
        vdat.pkt.nalu.dat = new std::vector<NaluItem *>;
        uint32_t left = len-(p-savep);
        do {
            uint32_t nalu_len = ENTOHL(*(uint32_t*)p);
            if (nalu_len + 4 > left) {
                LOGE("Error nalu format");
                break;
            }

            NaluItem *nitem =
               new NaluItem(nalu_len, new byte[nalu_len]);
            memcpy(nitem->second, p + 4, nalu_len);
            vdat.pkt.nalu.dat->push_back(nitem);

            p += (nalu_len + 4);
        } while ((left = len-(p-savep)) > 0);
        } break;

    case END_OF_SEQUENCE:
        vdat.pkt.dat = NULL;
        break;

    default:
        LOGE("Unknown AVCPktType %d", vdat.pkt.pkt_typ);
        return -1;
    }

    return 0;
}

int FLVParser::handle_video(FLVVideoTagData &vdat,
                            const byte strm[], uint32_t len)
{
    const byte *p = strm;

    *(byte *) &vdat = *p++; // codec_id & frame_typ
    switch (vdat.codec_id) {
    case CODECID_H264:
        return parse_avc(p, len-(p-strm), vdat);

    default:
        LOGE("Not supported codec id (%u)", vdat.codec_id);
        return -1;
    }

    if (p != strm + len) {
        LOGE("handle_video skipped %u bytes", len-(p-strm));
        return -1;
    }

    return 0;
}

int FLVParser::handle_audio(FLVAudioTagData &adat,
                            const byte strm[], uint32_t len)
{
    const byte *p = strm;

    *(byte *) &adat = *p++;
    if (adat.sound_fmt != 10 /* AAC */) {
        LOGE("Not support audio codec %u", adat.sound_fmt);
        return -1;
    }

    adat.aac.typ = *p++;
    switch (adat.aac.typ) {
    case 0: // AAC Sequence Header (2 bytes)
        memcpy(adat.aac.asc.dat, p, 2);
        p += 2;
#ifdef XDEBUG
        print_asc(adat.aac.asc);
#endif
        break;

    case 1: // AAC Raw
        adat.aac.dat.length = len-(p-strm);
        adat.aac.dat.strm = new byte[adat.aac.dat.length];
        memcpy(adat.aac.dat.strm, p, adat.aac.dat.length);
        break;

    default:
        LOGE("Invalid AAC pakcet type %u", adat.aac.typ);
        return -1;
    }

    return 0;
}

FLVParser::FLVTag* FLVParser::alloc_tag() const
{
    return (FLVTag *) calloc(1, sizeof(FLVTag));
}

int FLVParser::free_tag(FLVTag *&tag) const
{
    switch (tag->hdr.typ) {
    case TAG_AUDIO:
        free_audio_tag_dat(tag->dat.audio);
        break;

    case TAG_VIDEO:
        free_video_tag_dat(tag->dat.video);
        break;

    case TAG_SCRIPT:
        free_amf_list(&tag->dat.script);
        break;

    default:
        LOGE("Unknown tag type %u", tag->hdr.typ);
        break;
    }

    SAFE_FREE(tag);
    return 0;
}

int FLVParser::free_video_tag_dat(FLVVideoTagData &vdat)
{
    if (vdat.codec_id == CODECID_H264) {
        if (vdat.pkt.pkt_typ == SEQUENCE_HEADER) {
            SAFE_DELETE_ARRAY(vdat.pkt.avc_dcr.sps);
            SAFE_DELETE_ARRAY(vdat.pkt.avc_dcr.pps);
        } else if (vdat.pkt.pkt_typ == NALU) {
            FOR_VECTOR_ITERATOR(NaluItem *, *vdat.pkt.nalu.dat, it) {
                SAFE_DELETE_ARRAY((*it)->second);
                SAFE_DELETE(*it);
            }
            SAFE_DELETE(vdat.pkt.nalu.dat);
        } else {
            // fall through
        }
    } else {
        // fall through
    }
    return 0;
}

int FLVParser::free_audio_tag_dat(FLVAudioTagData &adat)
{
    if (adat.sound_fmt == 10 /* AAC */ &&
        adat.aac.typ == 1    /* AAC-raw */) {
        SAFE_DELETE_ARRAY(adat.aac.dat.strm);
    }
    return 0;
}

}
