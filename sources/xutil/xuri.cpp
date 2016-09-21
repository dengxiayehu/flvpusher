#include "xuri.h"
#include "xlog.h"

using namespace xutil;
using namespace std;

namespace xuri {

Uri::Uri() :
  protocol(NULL),
  username(NULL), password(NULL),
  host(NULL), port(80),
  path(NULL), option(NULL),
  buffer(NULL)
{
}

Uri::~Uri()
{
  cleanup();
}

char *Uri::decode_dup(const char *str)
{
  char *buf = strdup(str);
  if (!decode(buf))
    SAFE_FREE(buf);
  return buf;
}

char *Uri::decode(char *str)
{
  char *in = str, *out = str;
  if (!in) return NULL;

  char c;
  while ((c = *(in++)) != '\0') {
    if (c == '%') {
      char hex[3];
      if (!(hex[0] = *(in++)) || !(hex[1] = *(in++)))
        return NULL;
      hex[2] = '\0';
      *(out++) = (char) strtoul(hex, NULL, 0x10);
    } else
      *(out++) = c;
  }
  *out = '\0';
  return str;
}

bool Uri::isurisafe(int c)
{
  return ((unsigned char)(c - 'a') < 26)
      || ((unsigned char)(c - 'A') < 26)
      || ((unsigned char)(c - '0') < 10)
      || (strchr("-._~", c));
}

char *Uri::encode(const char *str, size_t *len)
{
  char *buf = (char *) malloc(3 * *len + 1);
  if (!buf) return NULL;

  char *out = buf;
  for (size_t i = 0; i < *len; ++i) {
    static const char hex[16+1] = "0123456789ABCDEF";
    unsigned char c = str[i];

    if (isurisafe(c))
      *(out++) = c;
    else {
      *(out++) = '%';
      *(out++) = hex[c >> 4];
      *(out++) = hex[c & 0xf];
    }
  }

  *len = out - buf;
  char *tmp = (char *) realloc(buf, *len + 1);
  out = tmp ? tmp : buf;
  out[*len] = '\0';
  return out;
}

static char *idna_to_ascii(const char *idn)
{
  for (const char *p = idn; *p; p++)
    if (((unsigned char)*p) >= 0x80)
      return NULL;

  return strdup(idn);
};

int Uri::parse(const char *str, unsigned char opt_sep)
{
  if (!str) return -1;

  cleanup();

  char *buf = strdup(str);
  if (!buf) return -1;
  buffer = buf;

  char *cur = buf, *next;
  next = buf;
  while ((*next >= 'A' && *next <= 'Z') || (*next >= 'a' && *next <= 'z')
      || (*next >= '0' && *next <= '9') || memchr("+-.", *next, 3))
    next++;
  if (!strncmp(next, "://", 3)) {
    *next = '\0';
    next += 3;
    protocol = cur;
    cur = next;
  }

  next = strchr(cur, '/');
  if (next) {
    path = next;
    if (opt_sep && (next = strchr(next, opt_sep))) {
      *(next++) = '\0';
      option = next;
    }
    *path = '\0';
  }

  next = strrchr(cur, '@');
  if (next) {
    *(next++) = '\0';
    username = cur;
    cur = next;

    next = strchr(username, ':');
    if (next) {
      *(next++) = '\0';
      password = next;
      decode(password);
    }
    decode(username);
  }

  if (*cur == '[' && (next = strrchr(cur, ']'))) {
    *(next++) = '\0';
    host = strdup(cur + 1);

    if (*next == ':')
      next++;
    else
      next = NULL;
  } else {
    next = strchr(cur, ':');
    if (next)
      *(next++) = '\0';

    host = idna_to_ascii(cur);
  }

  if (next)
    port = atoi(next);

  if (path)
    *path = '/';

  return 0;
}

map<string, string> Uri::parse_option(const char *option)
{
  map<string, string> result;
  if (option) {
    vector<string> kvvec(split(option, "&"));
    FOR_VECTOR_ITERATOR(string, kvvec, it) {
      vector<string> part(split(*it, "="));
      result[part[0]] = part[1];
    }
  }
  return result;
}

void Uri::cleanup()
{
  protocol = NULL;
  username = NULL;
  password = NULL;
  SAFE_FREE(host);
  port = 80;
  path = NULL;
  option = NULL;
  SAFE_FREE(buffer);
}

string Uri::to_string() const
{
  return sprintf_("protocol=%s, username=%s, password=%s, host=%s, port=%u, path=%s, option=%s",
                  protocol, username, password, host, port, path, option);
}

}
