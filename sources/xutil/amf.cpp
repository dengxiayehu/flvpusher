#include "amf.h"

#include <cstdlib>
#include <ctime>

#include "xlog.h"
#include "xutil.h"

using namespace xutil;

namespace amf {

ArrayItem::ArrayItem()
{
  first = alloc_amf();
  INIT_LIST_HEAD(&second);
}

ArrayItem::~ArrayItem()
{
  free_amf(first);
  free_amf_list(&second);
}

/////////////////////////////////////////////////////////////

int get_amf_string(const byte *&p, uint32_t len, AMFString &amfstr)
{
  // Parse string length (2 bytes)
  amfstr.len = ENTOHS(*((uint16_t *) p));
  if ((uint32_t) (amfstr.len + 2) > len) {
    LOGE("Not enough length(%u) for amfstr", len);
    return -1;
  }

  // Read string content (need to add trailing '\0')
  amfstr.str = new char[amfstr.len + 1];
  strncpy(amfstr.str, (char *) (p + 2), amfstr.len);
  amfstr.str[amfstr.len] = '\0';

  // Update the p pointer
  p += (2 + amfstr.len);
  return 0;
}

int get_amf_number(const byte *&p, uint32_t len, AMFNumber &amfnum)
{
  if (len < 8) {
    LOGE("Not enough length(%u) for amfnum", len);
    return -1;
  }

  amfnum.val = ENTOHLL(* (uint64_t *) p);
  p += 8;
  return 0;
}

int get_amf_bool(const byte *&p, uint32_t len, AMFBool &amfbool)
{
  if (len == 0) {
    LOGE("Not enough length(%u) for amfnum", len);
    return -1;
  }

  amfbool.b = *p++;
  return 0;
}

int get_amf_obj_end(const byte *&p, uint32_t len)
{
  if (len < 3)
    return -1;

  if (ENTOH24(p) != AMF_TYPE_OBJECT_END)
    return -1;

  p += sizeof(uint24_t);
  return 0;
}

int get_amf_associate_array(const byte *&p, uint32_t len,
    AMFAssociateArray &amfasoarr)
{
  const byte *savep = p;

  amfasoarr.sz = ENTOHL(* (uint32_t *) p);
  amfasoarr.arr = new std::vector<ArrayItem *>;
  p += sizeof(uint32_t);

  uint32_t idx = 0;
  while (idx < amfasoarr.sz) {
    ArrayItem *item = new ArrayItem;

    // AMFAssociateArray's first item is AMFString type
    if (get_amf_string(p, len-(p-savep), item->first->amfstr) < 0) {
      SAFE_DELETE(item);
      break;
    }
    item->first->typ = AMF_TYPE_STRING;

    // Second item is AMF type
    if (parse_amf(p, len-(p-savep), &item->second) < 0) {
      SAFE_DELETE(item);
      break;
    }

    amfasoarr.arr->push_back(item);
    ++idx;
  }

  // NOTE: ASSOCIATIVE_ARRAY should be followed by AMF_TYPE_END
  if (idx < amfasoarr.sz ||
      get_amf_obj_end(p, len-(p-savep)) < 0) {
    LOGE("Invalid format of AMF_TYPE_ASSOCIATIVE_ARRAY");
    free_amf_associate_array(amfasoarr);
    return -1;
  }

  return 0;
}

int get_amf_typobj(const byte *&p, uint32_t len, AMFObject &amftypobj)
{
  const byte *savep = p;
  bool error = false;

  amftypobj.arr = new std::vector<ArrayItem *>;
  for ( ; ; ) {
    ArrayItem *item = new ArrayItem;

    // AMFObject's first item is AMFString type
    if (get_amf_string(p, len-(p-savep), item->first->amfstr) < 0) {
      error = true;
      SAFE_DELETE(item);
      break;
    }
    item->first->typ = AMF_TYPE_STRING;

    // Check if AMF_TYPE_END reached
    if (item->first->amfstr.len == 0) {
      if (*p == AMF_TYPE_OBJECT_END) {
        ++p;
        SAFE_DELETE(item);
        break;
      }
    }

    // Second item is AMF type
    if (parse_amf(p, len-(p-savep), &item->second) < 0) {
      error = true;
      SAFE_DELETE(item);
      break;
    }

    amftypobj.arr->push_back(item);
  }

  if (error) {
    LOGE("Invalid format of AMF_TYPE_OBJECT");
    free_amf_typobj(amftypobj);
    return -1;
  }

  return 0;
}

int get_amf_array(const byte *&p, uint32_t len, AMFArray &amfarr)
{
  const byte *savep = p;

  amfarr.arr = new std::vector<struct list_head *>;
  amfarr.sz = ENTOHL(* (uint32_t *) p);
  p += sizeof(uint32_t);

  uint32_t idx = 0;
  while (idx < amfarr.sz) {
    struct list_head *head = new struct list_head;
    INIT_LIST_HEAD(head);
    if (parse_amf(p, len-(p-savep), head) < 0) {
      SAFE_DELETE(head);
      break;
    }

    amfarr.arr->push_back(head);
    ++idx;
  }

  if (idx < amfarr.sz) {
    LOGE("Invalid format of AMF_TYPE_ARRAY");
    free_amf_arr(amfarr);
    return -1;
  }

  return 0;
}

int get_amf_date(const byte *&p, uint32_t len, AMFDate &amfdate)
{
  if (len < 8 + 2) {
    LOGE("Not enough length(%u) for amfdate", len);
    return -1;
  }

  amfdate.msecs = ENTOHLL(* (uint64_t *) p);
  p += sizeof(uint64_t);
  amfdate.timezone = ENTOHS(* (int16_t *) p);
  p += sizeof(uint16_t);
  return 0;
}

int parse_amf(const byte *&p, uint32_t len, struct list_head *head)
{
  if (len == 0)
    return 0;

  const byte *savep = p;

  AMF *amfobj = alloc_amf(*p++);

  // Link this amfobj to head
  list_add_tail(&amfobj->list, head);

  switch (amfobj->typ) {
    case AMF_TYPE_NUMBER:
      if (get_amf_number(p, len-(p-savep), amfobj->amfnum) < 0) {
        LOGE("Failed to call get_amf_number() ");
        goto bail;
      }
      break;

    case AMF_TYPE_BOOL:
      if (get_amf_bool(p, len-(p-savep), amfobj->amfbool) < 0) {
        LOGE("Failed to call get_amf_bool() ");
        goto bail;
      }
      break;

    case AMF_TYPE_STRING:
      if (get_amf_string(p, len-(p-savep), amfobj->amfstr) < 0) {
        LOGE("Failed to call get_amf_string() ");
        goto bail;
      }
      break;

    case AMF_TYPE_OBJECT:
      if (get_amf_typobj(p, len-(p-savep), amfobj->amftypobj) < 0) {
        LOGE("Failed to call get_amf_typobj() ");
        goto bail;
      }
      break;

    case AMF_TYPE_ASSOCIATIVE_ARRAY:
      if (get_amf_associate_array(p, len-(p-savep), amfobj->amfasoarr) < 0) {
        LOGE("Failed to call get_amf_associate_array() ");
        goto bail;
      }
      break;

    case AMF_TYPE_ARRAY:
      if (get_amf_array(p, len-(p-savep), amfobj->amfarr) < 0) {
        LOGE("Failed to call get_amf_array() ");
        goto bail;
      }
      break;

    case AMF_TYPE_NULL:
    case AMF_TYPE_UNDEFINED:
    case AMF_TYPE_UNSUPPORTED:
      // No need to handle this type of amf
      break;

    case AMF_TYPE_DATE:
      if (get_amf_date(p, len-(p-savep), amfobj->amfdate) < 0) {
        LOGE("Failed to call get_amf_date() ");
        goto bail;
      }
      break;

    default:
      LOGE("Unsupported amfobj type: %d", amfobj->typ);
      goto bail;
      break;
  }

  return 0;

bail:
  list_del(&amfobj->list);
  free_amf(amfobj);
  return -1;
}

AMF *alloc_amf(byte typ)
{
  AMF *amfobj = (AMF *) calloc(1, sizeof(AMF));
  INIT_LIST_HEAD(&amfobj->list);
  amfobj->typ = typ;
  return amfobj;
}

void free_amf(AMF *&amfobj)
{
  switch (amfobj->typ) {
    case AMF_TYPE_STRING:
      free_amf_string(amfobj->amfstr);
      break;

    case AMF_TYPE_OBJECT:
      free_amf_typobj(amfobj->amftypobj);
      break;

    case AMF_TYPE_ASSOCIATIVE_ARRAY:
      free_amf_associate_array(amfobj->amfasoarr);
      break;

    case AMF_TYPE_ARRAY:
      free_amf_arr(amfobj->amfarr);
      break;

    default:
      break;
  }

  SAFE_FREE(amfobj);
}

void free_amf_list(struct list_head *head)
{
  struct list_head *pos, *n;
  list_for_each_safe(pos, n, head) {
    AMF *amfobj = list_entry(pos, AMF, list);
    list_del(pos);
    free_amf(amfobj);
  }
}

void free_amf_string(AMFString &amfstr)
{
  SAFE_DELETE_ARRAY(amfstr.str);
}

void free_amf_associate_array(AMFAssociateArray &amfasoarr)
{
  if (amfasoarr.arr) {
    FOR_VECTOR_ITERATOR(ArrayItem *, *amfasoarr.arr, it) {
      SAFE_DELETE(*it);
    }
  }
  SAFE_DELETE(amfasoarr.arr);
}

void free_amf_typobj(AMFObject &amftypobj)
{
  if (amftypobj.arr) {
    FOR_VECTOR_ITERATOR(ArrayItem *, *amftypobj.arr, it) {
      SAFE_DELETE(*it);
    }
  }
  SAFE_DELETE(amftypobj.arr);
}

void free_amf_arr(AMFArray &amfarr)
{
  if (amfarr.arr) {
    FOR_VECTOR_ITERATOR(struct list_head *, *amfarr.arr, it) {
      free_amf_list(*it);
      SAFE_DELETE(*it);
    }
  }
  SAFE_DELETE(amfarr.arr);
}

void print_amf_list(const char *indent, struct list_head *head)
{
  AMF *amfobj, *x;
  list_for_each_entry_safe(amfobj, x, head, list) {
    switch (amfobj->typ) {
      case AMF_TYPE_NUMBER:
        printf("%s%.2lf\n", indent,
               int2double(amfobj->amfnum.val));
        break;

      case AMF_TYPE_BOOL:
        printf("%s%s\n", indent,
               amfobj->amfbool.b ? "true" : "false");
        break;

      case AMF_TYPE_STRING:
        printf("%s%-24s\n", indent,
               amfobj->amfstr.str);
        break;

      case AMF_TYPE_OBJECT:
        printf("%sTYPE_OBJECT {\n", indent);
        if (amfobj->amftypobj.arr) { // In case it NULL
          FOR_VECTOR_ITERATOR(ArrayItem *, *amfobj->amftypobj.arr, it) {
            printf("%s%-24s : ", indent,
                   (*it)->first->amfstr.str);
            print_amf_list(sprintf_("%s\t", indent).c_str(),
                           &(*it)->second);
          }
        }
        printf("%s}\n", indent);
        break;

      case AMF_TYPE_ASSOCIATIVE_ARRAY:
        printf("%sASSOCIATE_ARRAY {\n", indent);
        if (amfobj->amfasoarr.arr) { // In case it NULL
          FOR_VECTOR_ITERATOR(ArrayItem *, *amfobj->amfasoarr.arr, it) {
            printf("%s%-24s : ", indent,
                   (*it)->first->amfstr.str);
            print_amf_list(sprintf_("%s\t", indent).c_str(),
                           &(*it)->second);
          }
        }
        printf("%s}\n", indent);
        break;

      case AMF_TYPE_ARRAY:
        printf("%sARRAY {\n", indent);
        if (amfobj->amfarr.arr) { // In case it NULL
          FOR_VECTOR_ITERATOR(struct list_head *, *amfobj->amfarr.arr, it) {
            print_amf_list(indent, *it);
          }
        }
        printf("%s}\n", indent);
        break;

      case AMF_TYPE_DATE: {
        time_t t = int2double(amfobj->amfdate.msecs)/1000;
        struct tm *ptm = localtime(&t);
        printf("%s%s %d\n", indent,
               sprintf_("%02d/%02d/%04d-%02d:%02d:%02d",
                        ptm->tm_mon+1, ptm->tm_mday, ptm->tm_year+1900,
                        ptm->tm_hour, ptm->tm_min, ptm->tm_sec).c_str(),
               amfobj->amfdate.timezone);
      } break;

      default:
        break;
    }
  }
}

int put_byte(byte *&p, byte val)
{
  *p++ = val;
  return 0;
}

// This is a special case for ASSOCIATIVE_ARRAY and so on
int put_amf_string_no_typ(byte *&p, const char *str)
{
  // Put string WITHOUT trailing '\0'
  uint16_t len = strlen(str);
  p = put_be16(p, len);
  memcpy(p, str, len);
  p += len;
  return 0;
}

int put_amf_string(byte *&p, const char *str)
{
  *p++ = AMF_TYPE_STRING;
  return put_amf_string_no_typ(p, str);
}

int put_amf_number(byte *&p, double val)
{
  *p++ = AMF_TYPE_NUMBER;
  p = put_be64(p, double2int(val));
  return 0;
}

int put_amf_bool(byte *&p, bool b)
{
  *p++ = AMF_TYPE_BOOL;
  *p++ = !!b;
  return 0;
}

int put_amf_obj_end(byte *&p)
{
  if (put_amf_string_no_typ(p, "") < 0) {
    return -1;
  }
  *p++ = AMF_TYPE_OBJECT_END;
  return 0;
}

int put_amf_associate_array(byte *&p,
    const AMFAssociateArray &amfasoarr)
{
  byte *savep = p;

  *p++ = AMF_TYPE_ASSOCIATIVE_ARRAY;
  p = put_be32(p, amfasoarr.arr ? amfasoarr.arr->size() : 0);

  if (amfasoarr.arr) {
    bool err = false;
    FOR_VECTOR_ITERATOR(ArrayItem *, *amfasoarr.arr, it) {
      put_amf_string_no_typ(p,
                            (*it)->first->amfstr.str);
      if (strm_amf_list(p, &(*it)->second) < 0) {
        LOGE("strm amfobj for aso-array failed");
        err = true;
        break;
      }
    }
    if (err) {
      // If failed, send already correctly streamed script
      p = savep;
      return -1;
    }
  }

  // Put OBJECT_END
  return put_amf_obj_end(p);
}

int put_amf_typobj(byte *&p, const AMFObject &amftypobj)
{
  byte *savep = p;

  *p++ = AMF_TYPE_OBJECT;

  if (amftypobj.arr) {
    bool err = false;
    FOR_VECTOR_ITERATOR(ArrayItem *, *amftypobj.arr, it) {
      put_amf_string_no_typ(p,
                            (*it)->first->amfstr.str);
      if (strm_amf_list(p, &(*it)->second) < 0) {
        LOGE("strm amfobj for amftypobj failed");
        err = true;
        break;
      }
    }
    if (err) {
      // If failed, send already correctly streamed script
      p = savep;
      return -1;
    }
  }

  return put_amf_obj_end(p);
}

int put_amf_array(byte *&p, const AMFArray &amfarr)
{
  byte *savep = p;

  *p++ = AMF_TYPE_ARRAY;
  p = put_be32(p, amfarr.arr ? amfarr.arr->size() : 0);

  if (amfarr.arr) {
    FOR_VECTOR_ITERATOR(struct list_head *, *amfarr.arr, it) {
      if (strm_amf_list(p, *it) < 0) {
        p = savep;
        return -1;
      }
    }
  }
  return 0;
}

int put_amf_date(byte *&p, const AMFDate &amfdate)
{
  *p++ = AMF_TYPE_DATE;
  p = put_be64(p, amfdate.msecs);
  p = put_be16(p, amfdate.timezone);
  return 0;
}

int strm_amf_list(byte *&p, struct list_head *head)
{
  byte *savep = p;

  AMF *amfobj, *x;
  list_for_each_entry_safe(amfobj, x, head, list) {
    switch (amfobj->typ) {
      case AMF_TYPE_NUMBER:
        if (put_amf_number(p, int2double(amfobj->amfnum.val)) < 0) {
          LOGE("Failed to call put_amf_number()");
          goto bail;
        }
        break;

      case AMF_TYPE_BOOL:
        if (put_amf_bool(p, amfobj->amfbool.b) < 0) {
          LOGE("Failed to call put_amf_bool()");
          goto bail;
        }
        break;

      case AMF_TYPE_STRING:
        if (put_amf_string(p, amfobj->amfstr.str) < 0) {
          LOGE("Failed to call put_amf_string()");
          goto bail;
        }
        break;

      case AMF_TYPE_OBJECT:
        if (put_amf_typobj(p, amfobj->amftypobj) < 0) {
          LOGE("Failed to call put_amf_typobj()");
          goto bail;
        }
        break;

      case AMF_TYPE_ASSOCIATIVE_ARRAY:
        if (put_amf_associate_array(p, amfobj->amfasoarr) < 0) {
          LOGE("Failed to call put_amf_associate_array()");
          goto bail;
        }
        break;

      case AMF_TYPE_ARRAY:
        if (put_amf_array(p, amfobj->amfarr) < 0) {
          LOGE("Failed to call put_amf_array()");
          goto bail;
        }
        break;

      case AMF_TYPE_DATE:
        if (put_amf_date(p, amfobj->amfdate) < 0) {
          LOGE("Failed to call put_amf_date()");
          goto bail;
        }
        break;

      default:
        LOGW("Not supported amfobj(%d) to stream",
             amfobj->typ);
        break;
    }
  }
  return 0;

bail:
  p = savep;
  return -1;
}

}
