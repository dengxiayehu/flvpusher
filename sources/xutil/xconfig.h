#ifndef _XCONFIG_H_
#define _XCONFIG_H_

#include "xutil.h"

namespace xconfig {

typedef int (*ConfigUpdateCB)(const char *conf_name, const char *value, void *user);

typedef enum {
  INTEGER = 0,
  BOOL,
  STRING,
  ENUM,
  UNKNOWN
} ConfigType;

class Config {
protected:
  Config() { }

public:
  virtual ~Config() { }

  virtual bool has_config(const char *conf_name) = 0;
  virtual char *get_config(const char *conf_name) = 0;
  virtual int set_config(const char *conf_name, const char *conf_value, const char *note = NULL) = 0;
  virtual int add_config(const char *conf_name, const char *conf_value, const char *note = NULL,
                         ConfigType type = STRING, const char *def = NULL, const char *range = NULL) = 0;
  virtual int del_config(const char *conf_name) = 0;
  virtual int register_config_update_cb(ConfigUpdateCB cb, void *user = NULL) = 0;
  virtual int register_config(const char *conf_name) = 0;
  virtual int unregister_config(const char *conf_name) = 0;
  virtual int register_all() = 0;
  virtual int unregister_all() = 0;

private:
  DISALLOW_COPY_AND_ASSIGN(Config);
};

Config *create_config(const char *config_path, volatile bool *watch_variable);
void destroy_config(Config **config);

#define GET_CONFIG_INT(c, x) do { \
  char *s = (c)->get_config(#x); \
  if (!s) { LOGE("No " #x " in config file"); assert(0); } \
  x = atoi(s); \
} while (0)
#define DECL_GET_CONFIG_INT(c, x) int x; GET_CONFIG_INT(c, x)

#define GET_CONFIG_BOOL(c, x) do { \
  char *s = (c)->get_config(#x); \
  if (!s) { LOGE("No " #x " in config file"); assert(0); } \
  if (s && !strncasecmp(s, "true", 4)) x = true; \
  else x = false; \
} while (0)
#define DECL_GET_CONFIG_BOOL(c, x) bool x; GET_CONFIG_BOOL(c, x)

#define GET_CONFIG_STRING(c, x) do { \
  char *s = (c)->get_config(#x); \
  if (!s) { LOGE("No " #x " in config file"); assert(0); } \
  x = s; \
} while (0)
#define DECL_GET_CONFIG_STRING(c, x) std::string x; GET_CONFIG_STRING(c, x)

}

#endif /* end of _XCONFIG_H_ */
