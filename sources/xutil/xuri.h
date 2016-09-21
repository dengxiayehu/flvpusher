#ifndef _XURI_H_
#define _XURI_H_

#include "xutil.h"

namespace xuri {

struct Uri {
  char *protocol;
  char *username;
  char *password;
  char *host;
  unsigned port;
  char *path;
  char *option;
  char *buffer;

  Uri();
  ~Uri();

  int parse(const char *str, unsigned char opt_sep = '?');
  void cleanup();
  std::string to_string() const;

  static char *decode_dup(const char *str);
  static char *decode(char *str);
  static bool isurisafe(int c);
  static char *encode(const char *str, size_t *len /* in-out */);
  static std::map<std::string, std::string> parse_option(const char *option);
};

}

#endif /* end of _XURI_H_ */
