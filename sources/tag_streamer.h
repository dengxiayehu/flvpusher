#ifndef _TAG_STREAMER_H_
#define _TAG_STREAMER_H_

#include <xutil.h>
#include <xfile.h>

#include "flv_parser.h"

namespace flvpusher {

class TagStreamerBase {
public:
    TagStreamerBase(const std::string &dump_path = "");
    virtual ~TagStreamerBase();

    virtual int process(FLVParser::FLVTag &tag)  = 0;

    int set_dump_path(const std::string &path);

    byte *get_strm() const;
    uint32_t get_strm_length () const;

protected:
    xfile::File m_file;
    xutil::MemHolder m_mem_holder;
    uint32_t m_strm_len;
};

/////////////////////////////////////////////////////////////

class VideoTagStreamer : public TagStreamerBase {
public:
    VideoTagStreamer(const std::string &dump_path = "")
        : TagStreamerBase(dump_path), m_sps_len(0), m_pps_len(0) { }

    virtual int process(FLVParser::FLVTag &tag);

private:
    byte m_sps[128]; // hope enough
    byte m_pps[128];
    uint32_t m_sps_len;
    uint32_t m_pps_len;
};

/////////////////////////////////////////////////////////////

class AudioTagStreamer : public TagStreamerBase {
public:
    AudioTagStreamer(const std::string &dump_path = "")
        : TagStreamerBase(dump_path) { }

    virtual int process(FLVParser::FLVTag &tag);

private:
    AudioSpecificConfig m_asc;
};

/////////////////////////////////////////////////////////////

class ScriptTagStreamer : public TagStreamerBase {
public:
    virtual int process(FLVParser::FLVTag &tag);
};

}

#endif /* end of _TAG_STREAMER_H_ */
