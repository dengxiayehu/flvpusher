#include "raw_parser.h"

#include <xlog.h>
#include <xmedia.h>

//#define XDEBUG

namespace flvpusher {

RawParserBase::RawParserBase() :
    m_raw_len(0)
{
}

RawParserBase::~RawParserBase()
{
}

/////////////////////////////////////////////////////////////

VideoRawParser::VideoRawParser() :
    m_sps_len(0),
    m_pps_len(0),
    m_key_frame(false),
    m_sps_pps_changed(false)
{
}

VideoRawParser::~VideoRawParser()
{
    reset();
}

void VideoRawParser::reset()
{
    FOR_VECTOR_ITERATOR(NaluItem *, m_nalus, it) {
        SAFE_DELETE(*it);
    }
    m_nalus.clear();

    m_key_frame = false;
    m_sps_pps_changed = false;
}

int VideoRawParser::process(byte *dat, uint32_t len)
{
    reset();

    /* Split nalus into vector m_nalus
     * TODO: Find a better way */

    byte *end = dat + len;
    uint32_t nalu_ignored = 0;

    for ( ; ; ) {
        bool startcoede_found = false;

        while (dat != end) {
            if (STARTCODE3(dat)) {  // If next 24 bits are 0x000001
                startcoede_found = true;
                break;
            } else {
                ++dat;              // Flush 8 bits
            }
        }

        if (startcoede_found) {     // If startcoede found
            dat += 3;               // Flush the startcode found

            // Record this nalu_start addr
            byte *nalu_start = dat;

            // Now navigate up to next startcode and store the in between stuff
            while (dat != end) {
                // Get next 24 bits & check if it equals to 0x000001
                if (!STARTCODE3(dat)) {
                    // Search for pattern 0x000000
                    if (!(dat[0]==0 && dat[1]==0 && dat[2]==0)) {
                        // Copy one byte to the nal (just backward)
                        ++dat;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

            // We got a nalu item
            if (dat - nalu_start > 0) { // If extra startcode founded, ignore it
                // Update the sps & pps if there is
                byte nalu_typ = (*nalu_start)&0x1F;
                if (nalu_typ == 7 /*SPS*/) {
                    // Check whether sps has changed
                    if (m_sps_len != 0 &&
                        (m_sps_len != (uint32_t) (dat-nalu_start) ||
                         memcmp(m_sps, nalu_start, m_sps_len))) {
                        m_sps_pps_changed = true;
                    }
                    
                    m_sps_len = dat-nalu_start;
                    memcpy(m_sps, nalu_start, m_sps_len);

                    // Indicate this a key frame
                    m_key_frame = true;
                } else if (nalu_typ == 8 /*PPS*/) {
                    // Check whether sps has changed
                    if (m_pps_len != 0 &&
                        (m_pps_len != (uint32_t) (dat-nalu_start) ||
                         memcmp(m_pps, nalu_start, m_pps_len))) {
                        m_sps_pps_changed = true;
                    }
                    
                    m_pps_len = dat-nalu_start;
                    memcpy(m_pps, nalu_start, m_pps_len);

                    m_key_frame = true; // ditto
                } else if (nalu_typ == 6) {
                    m_key_frame = true; // ditto
                }

                m_nalus.push_back(
                        new NaluItem(dat-nalu_start, nalu_start));
            } else {
                ++nalu_ignored;
            }
        } else {
            break;
        }
    }

#ifdef XDEBUG
    LOGD("Video nalus#: %u, ignored#: %u",
            m_nalus.size(), nalu_ignored);
    if (m_key_frame) {
        LOGD("m_sps_len=%u, first 4 bytes is: %02x %02x %02x %02x",
             m_sps_len, m_sps[0], m_sps[1], m_sps[2], m_sps[3]);
        LOGD("m_pps_len=%u, first 4 bytes is: %02x %02x %02x %02x",
             m_pps_len, m_pps[0], m_pps[1], m_pps[2], m_pps[3]);
    }
    uint32_t nalu_len = 0;
    FOR_VECTOR_ITERATOR(NaluItem *, m_nalus, it) {
        LOGD("length=%u, first 4 bytes is: %02x %02x %02x %02x",
             (*it)->first,
             (*it)->second[0], (*it)->second[1],
             (*it)->second[2], (*it)->second[3]);
        nalu_len += (*it)->first;
    }
    if (nalu_len + (m_nalus.size() + nalu_ignored)*4 != len) {
        LOGW("Parse startcode from video frame failed (ignored)");
    }
#endif
    return 0;
}

const byte *VideoRawParser::get_nalu_data(uint32_t idx) const
{
    if (idx >= m_nalus.size()) {
        LOGE("idx %d out of nalu vector", idx);
        return NULL;
    }

    return m_nalus[idx]->second;
}

uint32_t VideoRawParser::get_nalu_length(uint32_t idx) const
{
    if (idx >= m_nalus.size()) {
        LOGE("idx %d out of nalu vector", idx);
        return NULL;
    }

    return m_nalus[idx]->first;
}

/////////////////////////////////////////////////////////////

int AudioRawParser::process(byte *dat, uint32_t len)
{
    if (len < 7) { // 7 is for ADTS header's length
        LOGE("Audio frame length %u error", len);
        return -1;
    }

    // ADTS header should be there, check syncword
    if (!(dat[0]==0xFF && (dat[1]&0xF0)==0xF0)) {
        LOGE("Bad syncword for ADTS header");
        return -1;
    }

    // Update asc
    adts_header2asc(dat, m_asc);

    m_raw_len = len - 7;
    byte *buf = (byte *) m_mem_holder.alloc(m_raw_len);
    memcpy(buf, dat+7, m_raw_len);
    return 0;
}

void AudioRawParser::adts_header2asc(
        const byte adts_header[7], byte asc[2])
{
    byte profile = (adts_header[2]&0xC0)>>6;                    // 2 bits
    byte sample_rate_idx = (adts_header[2]&0x3C)>>2;            // 4 bits
    byte channel =
        ((adts_header[2]&0x01)<<2)|(adts_header[3]&0xC0)>>6;    // 3 bits

#ifdef XDEBUG
    LOGI("profile=%u, sample_rate_idx=%u, channel=%u",
         profile, sample_rate_idx, channel);
#endif

    asc[0] = ((profile+1)<<3)|((sample_rate_idx&0x0E)>>1);
    asc[1] = ((sample_rate_idx&0x01)<<7)|(channel<<3);
}

}
