#ifndef _AMF_H_
#define _AMF_H_

#include <vector>

#include "xutil.h"
#include "list.h"

namespace amf {

using xutil::status_t;

enum {
  MONO    = 0,
  STEREO  = 1
};

enum AMFType {
  AMF_TYPE_NUMBER             = ((byte) 0x00),
  AMF_TYPE_BOOL               = ((byte) 0x01),
  AMF_TYPE_STRING             = ((byte) 0x02),
  AMF_TYPE_OBJECT             = ((byte) 0x03),
  AMF_TYPE_NULL               = ((byte) 0x05),
  AMF_TYPE_UNDEFINED          = ((byte) 0x06),
  AMF_TYPE_REFERENCE          = ((byte) 0x07),
  AMF_TYPE_ASSOCIATIVE_ARRAY  = ((byte) 0x08),
  AMF_TYPE_OBJECT_END         = ((byte) 0x09),
  AMF_TYPE_ARRAY              = ((byte) 0x0A),
  AMF_TYPE_DATE               = ((byte) 0x0B),
  AMF_TYPE_UNSUPPORTED        = ((byte) 0x0D),
  AMF_TYPE_END
};

struct AMFNumber {
  uint64_t val;
};

struct AMFBool {
  byte b;
};

struct AMFString {
  uint16_t len;
  char *str;
};

struct AMFDate {
  uint64_t msecs;
  int16_t timezone;
};

struct AMF;
struct ArrayItem : std::pair<AMF *, struct list_head> {
  ArrayItem();
  ~ArrayItem();
};

struct AMFAssociateArray {
  std::vector<ArrayItem *> *arr;
  uint32_t sz;
};

struct AMFArray {
  std::vector<struct list_head *> *arr;
  uint32_t sz;
};

struct AMFObject {
  std::vector<ArrayItem *> *arr;
};

struct AMF {
  struct list_head list;
  byte typ;
  union {
    AMFNumber amfnum;
    AMFBool amfbool;
    AMFString amfstr;
    AMFDate amfdate;
    AMFAssociateArray amfasoarr;
    AMFArray amfarr;
    AMFObject amftypobj;
  };
};

typedef struct list_head AMFData;

int parse_amf(const byte *&buff, uint32_t len, struct list_head *head);
int get_amf_string(const byte *&p, uint32_t len, AMFString &amfstr);
int get_amf_number(const byte *&p, uint32_t len, AMFNumber &amfnum);
int get_amf_bool(const byte *&p, uint32_t len, AMFNumber &amfbool);
int get_amf_associate_array(const byte *&p, uint32_t len,
                            AMFAssociateArray &amfasoarr);
int get_amf_array(const byte *&p, uint32_t len, AMFArray &amfarr);
int get_amf_typobj(const byte *&p, uint32_t len, AMFObject &amftypobj);
int get_amf_date(const byte *&p, uint32_t len, AMFDate &amfdate);
int get_amf_obj_end(const byte *&p, uint32_t len);

int put_byte(byte *&p, byte val);
int put_amf_string_no_typ(byte *&p, const char *str);
int put_amf_string(byte *&p, const char *str);
int put_amf_number(byte *&p, double val);
int put_amf_bool(byte *&p, bool b);
int put_amf_obj_end(byte *&p);
int put_amf_associate_array(byte *&p,
                            const AMFAssociateArray &amfasoarr);
int put_amf_typobj(byte *&p, const AMFObject &amftypobj);
int put_amf_array(byte *&p, const AMFArray &amfarr);

AMF *alloc_amf(byte typ = AMF_TYPE_END);
void free_amf_list(struct list_head *head);
void free_amf(AMF *&amfobj);
void free_amf_string(AMFString &amfstr);
void free_amf_associate_array(AMFAssociateArray &amfasoarr);
void free_amf_typobj(AMFObject &amftypobj);
void free_amf_arr(AMFArray &amfarr);

void print_amf_list(const char *indent, struct list_head *head);

int strm_amf_list(byte *&p, struct list_head *head);

union uint64double {
  uint64_t ival;
  double fval;
};
static inline double int2double(uint64_t val)
{
  union uint64double x;
  x.ival = val;
  return x.fval;
}
static inline uint64_t double2int(double val)
{
  union uint64double x;
  x.fval = val;
  return x.ival;
}

}

#endif /* end of _AMF_H_ */
