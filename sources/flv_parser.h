#ifndef _FLV_PARSER_H_
#define _FLV_PARSER_H_

#include <xlog.h>
#include <xfile.h>
#include <xutil.h>
#include <xmedia.h>

#include "common.h"
#include "xutil/amf.h"

using namespace xmedia;

namespace flvpusher {

class FLVParser {
public:
    FLVParser();
    ~FLVParser();

    int set_file(const std::string &flv_file);

    bool eof() const;

public:
    #pragma pack(1)
    /////////////////////////////////////////////////////////////
    // FLV header structure (little-endian)
    /////////////////////////////////////////////////////////////
    struct FLVHeader {
        byte signature[3];   // flv file starts with first 3 bytes "FLV"
        byte version;        // version
        byte video : 1;      // whether has video
        byte : 1;
        byte audio : 1;      // whether has audio
        byte : 5;
        uint32_t dataoffset; // flv's header length(version 1 should be always 9)
    };

    /////////////////////////////////////////////////////////////
    // Tag header structure
    /////////////////////////////////////////////////////////////
    enum TagHeaderType {
        TAG_AUDIO   = (byte) 0x08,
        TAG_VIDEO   = (byte) 0x09,
        TAG_SCRIPT  = (byte) 0x12
    };

    struct FLVTagHeader {
        byte typ;
        uint24_t datasize;
        uint24_t timestamp;
        byte timestamp_ext;
        uint24_t stream_id;
    };

    /////////////////////////////////////////////////////////////
    // Tag data structure
    /////////////////////////////////////////////////////////////
    // Audio structures
    struct AACData {
        byte *strm;
        uint32_t length;
    };
    struct AAC {
        byte typ;
        union {
            AudioSpecificConfig asc;
            AACData dat;
        };
    };
    struct FLVAudioTagData {
        byte sound_typ : 1;
        byte sound_size : 1;
        byte sound_rate : 2;
        byte sound_fmt : 4;
        union {
            AAC aac;
            byte *other;
        };
    };

    /////////////////////////////////////////////////////////////
    // Video structures
    struct AVCVideoPacket {
        byte pkt_typ;
        uint24_t compostion_time;
        union {
            AVCDecorderConfigurationRecord avc_dcr;
            Nalu nalu;
            byte *dat;
        };
    };
    enum { KEY_FRAME = (byte ) 0x01 };
    struct FLVVideoTagData {
        byte codec_id : 4;
        byte frame_typ : 4;
        AVCVideoPacket pkt;
    };

    enum CodecID{
        CODECID_JPEG    = (byte) 0x01,
        CODECID_H263    = (byte) 0x02,
        CODECID_SCREEN  = (byte) 0x03,
        CODECID_VP6     = (byte) 0x04,
        CODECID_VP6A    = (byte) 0x05,
        CODECID_SCREEN2 = (byte) 0x06,
        CODECID_H264    = (byte) 0x07
    };

    enum AVCPktType {
        SEQUENCE_HEADER = (byte) 0x00,
        NALU            = (byte) 0x01,
        END_OF_SEQUENCE = (byte) 0x02,
    };
    struct FLVTagData {
        union {
            amf::AMFData script;
            FLVVideoTagData video;
            FLVAudioTagData audio;
        };
    };
    
    /////////////////////////////////////////////////////////////
    // Tag structure (tag-header + tag-data)
    /////////////////////////////////////////////////////////////
    struct FLVTag {
        FLVTagHeader hdr;
        FLVTagData dat;
    };
    #pragma pack()

public:
    int read_header(FLVHeader &hdr,
            uint8_t *buf = NULL, uint32_t buf_size = 0) const;
    int read_tag(FLVTag *&tag,
            uint8_t *buf = NULL, uint32_t buf_size = 0);
    FLVTag *alloc_tag() const;
    int free_tag(FLVTag *&tag) const;

private:
    static int free_video_tag_dat(FLVVideoTagData &vdat);
    static int free_audio_tag_dat(FLVAudioTagData &adat);

    static int handle_script(amf::AMFData &script,
            const byte strm[], uint32_t len);
    static int handle_video(FLVVideoTagData &vdat,
            const byte strm[], uint32_t len);
    static int handle_audio(FLVAudioTagData &adat,
            const byte strm[], uint32_t len);

    static int parse_avc(const byte *&p, uint32_t len,
            FLVVideoTagData &vdat);

private:
    xfile::File m_file;

    xutil::MemHolder m_mem_holder;
};

}

#endif /* end of _FLV_PARSER_H_ */
