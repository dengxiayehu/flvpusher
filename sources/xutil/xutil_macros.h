#ifndef _XUTIL_MACROS_H_
#define _XUTIL_MACROS_H_

#ifndef SAFE_DELETE
#  define SAFE_DELETE(p) do {   \
  delete p;                     \
  p = NULL;                     \
} while (0)
#endif
#ifndef SAFE_DELETE_ARRAY
#  define SAFE_DELETE_ARRAY(p) do { \
  delete [] p;                      \
  p = NULL;                         \
} while (0)
#  define SAFE_DELETEA SAFE_DELETE_ARRAY
#endif

#ifndef SAFE_FREE
#  define SAFE_FREE(p) do {       \
  free(p);                        \
  p = NULL;                       \
} while (0)
#endif

#ifndef SAFE_CLOSE
#  define SAFE_CLOSE(fd)    do {  \
  if (fd >= 0) {                  \
    ::close(fd);                  \
    fd = -1;                      \
  }                               \
} while (0)
#endif

#define CHECK_EXPR_EXEC(expr, cmd) do { \
  if (expr) { cmd; }                    \
} while (0)
#define CHECK_EXPR_EXEC_RET(expr, cmd) do { \
  if (expr) { cmd; return; }                \
} while (0);
#define CHECK_EXPR_EXEC_RETVAL(expr, cmd, retval) do {  \
  if (expr) { cmd; return retval; }                     \
} while (0);

#define CHECK_EXPR_EXEC_GOTO(expr, cmd, label) do { \
  if (expr) { cmd; goto label; }                    \
} while (0)

#define DISALLOW_COPY_AND_ASSIGN(TypeName)  \
  TypeName(const TypeName &);               \
void operator=(const TypeName &)

#include <sys/syscall.h>  
#define gettid() syscall(__NR_gettid)

#define NELEM(arr)  (sizeof(arr)/sizeof(arr[0]))

#define BEGIN   {
#define END     }

#define MIN(x, y) ({ \
  typeof(x) _min1 = (x); \
  typeof(y) _min2 = (y); \
  (void) (&_min1 == &_min2); \
  _min1 < _min2 ? _min1 : _min2; })
#define MAX(x, y) ({ \
  typeof(x) _min1 = (x); \
  typeof(y) _min2 = (y); \
  (void) (&_min1 == &_min2); \
  _min1 > _min2 ? _min1 : _min2; })

#define foreach(container,it) \
  for (typeof((container).begin()) it = (container).begin(); \
    it != (container).end(); \
    ++it)

#define FOR_VECTOR_ITERATOR(e,v,i) for(std::vector<e>::iterator i=(v).begin();i!=(v).end();i++)
#define FOR_VECTOR_CONST_ITERATOR(e,v,i) for(std::vector<e>::const_iterator i=(v).begin();i!=(v).end();i++)
#define FOR_MAP(m,k,v,i) for(std::map<k , v>::iterator i=(m).begin();i!=(m).end();i++)
#define FOR_MAP_CONST(m,k,v,i) for(std::map<k , v>::const_iterator i=(m).begin();i!=(m).end();i++)
#define MAP_KEY(i) ((i)->first)
#define MAP_VAL(i) ((i)->second)
#define FOR_SET(e,s,i) for(std::set<e>::iterator i=(s).begin();i!=(s).end();i++)

#define FATAL(fmt, ...) do {              \
  fprintf(stderr, fmt, ##__VA_ARGS__);    \
  fprintf(stderr, "\n");                  \
} while (0)

/////////////////////////////////////////////////////////////

#include <arpa/inet.h>

#include "xtype.h"

//64 bit
#ifndef DONT_DEFINE_HTONLL
#define htonll(x) \
  ((uint64_t)( \
    ((((uint64_t)(x)) & 0xff00000000000000LL) >> 56) |  \
    ((((uint64_t)(x)) & 0x00ff000000000000LL) >> 40) |  \
    ((((uint64_t)(x)) & 0x0000ff0000000000LL) >> 24) |  \
    ((((uint64_t)(x)) & 0x000000ff00000000LL) >> 8) |   \
    ((((uint64_t)(x)) & 0x00000000ff000000LL) << 8) |   \
    ((((uint64_t)(x)) & 0x0000000000ff0000LL) << 24) |  \
    ((((uint64_t)(x)) & 0x000000000000ff00LL) << 40) |  \
    ((((uint64_t)(x)) & 0x00000000000000ffLL) << 56)    \
    ))
#define ntohll(x)   htonll(x)
#endif /* DONT_DEFINE_HTONLL */

//64 bit
#define EHTONLL(x) htonll(x)
#define ENTOHLL(x) ntohll(x)

#define REVERSE_BYTES(bytes_arr, n)   do {    \
  for (uint32_t idx = 0; idx < n/2; ++idx) {  \
    byte tmp = *bytes_arr[idx]; \
    *bytes_arr[idx] = *bytes_arr[n - idx - 1];\
    *bytes_arr[n - idx - 1] = tmp; \
  }                                           \
} while (0)

// 24 bit
#define ENDIAN_CHANGE_UI24(x)   REVERSE_BYTES((byte *) &(x), 3)
#define VALUI24(x)              \
  ((uint32_t)((x)[2]<<16) + (uint32_t)((x)[1]<<8) + (uint32_t)(x)[0])

// 32 bit
#define EHTONL(x) htonl(x)
#define ENTOHL(x) ntohl(x)

#define ENTOH24(x)              (((x)[0] << 16) + ((x)[1] << 8) + (x)[2])
#define INITUI24(x, val) do { \
  x[2] = (val&0xFF0000)>>16;  \
  x[1] = (val&0xFF00)>>8;     \
  x[0] = val&0xFF;            \
} while (0)

// 16 bit
#define EHTONS(x) htons(x)
#define ENTOHS(x) ntohs(x)

#define REVERSE_BYTE(b) do {              \
  byte x = 0;                             \
  for (uint8_t idx = 0; idx < 8; ++idx) { \
    x |= ((b & 0x01) << (8 - idx - 1));   \
    b >>= 1;                              \
  }                                       \
  b = x;                                  \
} while (0)

#define STR(x) (((std::string)(x)).c_str())

#define UNUSED(x)   ((void) (x))

#define DIRSEP '/'

#include <limits.h>
#include <stdlib.h>
#define ABS_PATH(rel, abs, abs_size) realpath((rel), (abs))

#define MAKEFOURCC(ch0, ch1, ch2, ch3) \
  ((uint32_t)(uint8_t)(ch0) | ((uint32_t)(uint8_t)(ch1) << 8) | \
   ((uint32_t)(uint8_t)(ch2) << 16) | ((uint32_t)(uint8_t)(ch3) << 24 ))

#define MAKE_TAG8(a,b,c,d,e,f,g,h) ((uint64_t)(((uint64_t)(a))<<56)|(((uint64_t)(b))<<48)|(((uint64_t)(c))<<40)|(((uint64_t)(d))<<32)|(((uint64_t)(e))<<24)|(((uint64_t)(f))<<16)|(((uint64_t)(g))<<8)|((uint64_t)(h)))
#define MAKE_TAG7(a,b,c,d,e,f,g) MAKE_TAG8(a,b,c,d,e,f,g,0)
#define MAKE_TAG6(a,b,c,d,e,f) MAKE_TAG7(a,b,c,d,e,f,0)
#define MAKE_TAG5(a,b,c,d,e) MAKE_TAG6(a,b,c,d,e,0)
#define MAKE_TAG4(a,b,c,d) MAKE_TAG5(a,b,c,d,0)
#define MAKE_TAG3(a,b,c) MAKE_TAG4(a,b,c,0)
#define MAKE_TAG2(a,b) MAKE_TAG3(a,b,0)
#define MAKE_TAG1(a) MAKE_TAG2(a,0)

#endif /* end of _XUTIL_MACROS_H_ */
