#include <sys/inotify.h>

#include "xconfig.h"
#include "xlog.h"
#include "xfile.h"

using namespace xutil;
using namespace xfile;
using namespace std;

namespace xconfig {

class ConfigImpl : public Config {
public:
  ConfigImpl();
  virtual ~ConfigImpl();

  virtual bool has_config(const char *conf_name);
  virtual char *get_config(const char *conf_name);
  virtual int set_config(const char *conf_name, const char *conf_value, const char *note = NULL);
  virtual int add_config(const char *conf_name, const char *conf_value, const char *note = NULL,
                         ConfigType type = STRING, const char *def = NULL, const char *range = NULL);
  virtual int del_config(const char *conf_name);
  virtual int register_config_update_cb(ConfigUpdateCB cb, void *user = NULL);
  virtual int register_config(const char *conf_name);
  virtual int unregister_config(const char *conf_name);
  virtual int register_all();
  virtual int unregister_all();

public:
  int load(const char *config_path);
  int start_monitor(volatile bool *watch_variable);
  int stop_monitor();

private:
  struct ConfigItem {
    char *name;
    char *value;
    ConfigType type;
    char *def;
    char *range;
    char *note;

    ConfigItem();
    ConfigItem(char *name_, char *value_,
               char *typestr, char *def_, char *range_, char *note_);
    ~ConfigItem();

    bool is_valid() const;

    static ConfigType str2type(const char *typestr);
    static const char *type2str(ConfigType type);
    static bool check_integer(const char *value, char *range);
    static bool check_bool(const char *value);
    static bool check_string(const char *value);
    static bool check_enum(const char *value, char *range);
  };

private:
  static bool is_delime(char *&pch);

private:
  DISALLOW_COPY_AND_ASSIGN(ConfigImpl);
  DECL_THREAD_ROUTINE(ConfigImpl, monitor_routine);
  Thread *m_thrd;
  volatile bool *m_watch_variable;
  map<ConfigUpdateCB, void *> m_cb_map;
  set<string> m_reg;
  map<string, ConfigItem *> m_map;
  string m_path;
  RecursiveMutex m_mutex;
  int m_ctl[2];
};

ConfigImpl::ConfigItem::ConfigItem() :
  name(NULL), value(NULL), type(UNKNOWN), def(NULL), range(NULL), note(NULL)
{
}

ConfigImpl::ConfigItem::ConfigItem(char *name_, char *value_,
                                   char *typestr, char *def_, char *range_, char *note_) :
  name(strdup_(name_)), value(strdup_(value_)),
  type(str2type(typestr)),
  def(strdup_(def_)), range(strdup_(range_)),
  note(strdup_(note_))
{
}

ConfigImpl::ConfigItem::~ConfigItem()
{
  SAFE_FREE(name); SAFE_FREE(value);
  SAFE_FREE(def); SAFE_FREE(range);
  SAFE_FREE(note);
}

bool ConfigImpl::ConfigItem::is_valid() const
{
  switch (type) {
    case INTEGER:   return check_integer(value, range);
    case BOOL:      return check_bool(value);
    case STRING:    return check_string(value);
    case ENUM:      return check_enum(value, range);
    case UNKNOWN:
    default:        return !def && !range ? true : false;
  }
}

ConfigType ConfigImpl::ConfigItem::str2type(const char *typestr)
{
  if (!typestr) return UNKNOWN;
  else if (!strncasecmp(typestr, "INTEGER", 7))
    return INTEGER;
  else if (!strncasecmp(typestr, "BOOL", 4))
    return BOOL;
  else if (!strncasecmp(typestr, "STRING", 6))
    return STRING;
  else if (!strncasecmp(typestr, "ENUM", 4))
    return ENUM;
  else
    return UNKNOWN;
}

const char *ConfigImpl::ConfigItem::type2str(ConfigType type)
{
  switch (type) {
    case INTEGER:   return "INTEGER";
    case BOOL:      return "BOOL";
    case STRING:    return "STRING";
    case ENUM:      return "ENUM";
    case UNKNOWN:
    default:        return "UNKNOWN";
  }
}

bool ConfigImpl::ConfigItem::check_integer(const char *value, char *range)
{
  if (!range) return true;

  range = skip_blank(range);
  if (*range) {
    char r1[128], r2[128], *pdst;
    for (pdst = r1; *range && !isspace(*range) && *range != '~'; ++range)
      *pdst++ = *range;
    *pdst = '\0';
    if (r1[0] && (range = strchr(range, '~'))) {
      range = skip_blank(range + 1);
      if (*range) {
        for (pdst = r2; *range && !isspace(*range); ++range)
          *pdst++ = *range;
        *pdst = '\0';
        return atol(value) >= atol(r1) && atol(value) <= atol(r2);
      }
    }
  }
  return false;
}

bool ConfigImpl::ConfigItem::check_bool(const char *value)
{
  return value && (!strncasecmp(value, "true", 4) || !strncasecmp(value, "false", 5));
}

bool ConfigImpl::ConfigItem::check_string(const char *value)
{
  return value && strlen(value);
}

bool ConfigImpl::ConfigItem::check_enum(const char *value, char *range)
{
  char *candinates[128];
  int n = 0;
again:
  range = skip_blank(range);
  if (*range) {
    char enumstr[128], *pdst;
    for (pdst = enumstr; *range && !isspace(*range) && *range != ','; ++range)
      *pdst++ = *range;
    *pdst = '\0';
    candinates[n++] = strdup(enumstr);
    if ((*range == ',' && *++range) || (range = skip_blank(range), *range)) goto again;
  }
  bool retval = false;
  for (int i = 0; i < n; ++i) {
    if (!strcasecmp(candinates[i], value))
      retval = true;
    SAFE_FREE(candinates[i]);
  }
  return retval;
}

ConfigImpl::ConfigImpl() :
  m_thrd(NULL), m_watch_variable(NULL)
{
  m_ctl[0] = m_ctl[1] = -1;
}

ConfigImpl::~ConfigImpl()
{
  FOR_MAP(m_map, string, ConfigItem *, it)
    SAFE_DELETE(MAP_VAL(it));
}

bool ConfigImpl::is_delime(char *&pch)
{
  if (*pch == '\\') {
    ++pch;
    return false;
  }
  return isspace(*pch) || *pch == ':' || *pch == '=';
}

bool ConfigImpl::has_config(const char *conf_name)
{
  AutoLock _l(m_mutex);

  return conf_name && m_map.find(conf_name) != m_map.end();
}

char *ConfigImpl::get_config(const char *conf_name)
{
  AutoLock _l(m_mutex);

  if (!has_config(conf_name)) return NULL;
  return MAP_VAL(m_map.find(conf_name))->value;
}

int ConfigImpl::set_config(const char *conf_name, const char *conf_value, const char *note)
{
  AutoLock _l(m_mutex);

  if (!has_config(conf_name)) {
    LOGE("Non exists config item \"%s\"", conf_name);
    return -1;
  }
  ConfigItem *item = MAP_VAL(m_map.find(conf_name));
  if (!m_cb_map.empty() &&
      strcmp(conf_value, item->value) &&
      m_reg.find(conf_name) != m_reg.end()) {
    FOR_MAP(m_cb_map, ConfigUpdateCB, void *, it)
      (MAP_KEY(it))(conf_name, conf_value, MAP_VAL(it));
  }
  SAFE_FREE(item->value);
  item->value = strdup_(conf_value);
  SAFE_FREE(item->note);
  item->note = strdup_(note);
  return 0;
}

int ConfigImpl::add_config(const char *conf_name, const char *conf_value, const char *note,
                           ConfigType type, const char *def, const char *range)
{
  AutoLock _l(m_mutex);

  if (has_config(conf_name)) {
    LOGE("Duplicated config item \"%s\"", conf_name);
    return -1;
  }
  ConfigItem *item = new ConfigItem((char *) conf_name, (char *) conf_value,
                                    (char *) ConfigItem::type2str(type), (char *) def, (char *) range, (char *) note);
  if (!item->is_valid()) {
    SAFE_DELETE(item);
    return -1;
  }
  m_map[conf_name] = item;
  return 0;
}

int ConfigImpl::del_config(const char *conf_name)
{
  AutoLock _l(m_mutex);

  if (!has_config(conf_name)) return -1;
  map<string, ConfigItem *>::iterator itm = m_map.find(conf_name);
  if (!m_cb_map.empty()) {
    set<string>::iterator its = m_reg.find(conf_name);
    if (its != m_reg.end()) {
      FOR_MAP(m_cb_map, ConfigUpdateCB, void *, it)
        (MAP_KEY(it))(MAP_VAL(itm)->name, NULL, MAP_VAL(it));
      m_reg.erase(its);
    }
  }
  SAFE_DELETE(MAP_VAL(itm));
  m_map.erase(itm);
  return 0;
}

int ConfigImpl::register_config_update_cb(ConfigUpdateCB cb, void *user)
{
  AutoLock _l(m_mutex);

  m_cb_map[cb] = user;
  return 0;
}

int ConfigImpl::register_config(const char *conf_name)
{
  AutoLock _l(m_mutex);

  if (!has_config(conf_name)) {
    LOGE("Non exists config item \"%s\" to register", conf_name);
    return -1;
  }
  m_reg.insert(conf_name);
  return 0;
}

int ConfigImpl::unregister_config(const char *conf_name)
{
  AutoLock _l(m_mutex);

  if (!has_config(conf_name)) {
    LOGE("Non exists config item \"%s\" to unregister", conf_name);
    return -1;
  }
  m_reg.erase(conf_name);
  return 0;
}

int ConfigImpl::register_all()
{
  AutoLock _l(m_mutex);

  FOR_MAP_CONST(m_map, string, ConfigItem *, it)
    m_reg.insert(MAP_KEY(it));
  return 0;
}

int ConfigImpl::unregister_all()
{
  AutoLock _l(m_mutex);

  m_reg.clear();
  return 0;
}

int ConfigImpl::load(const char *config_path)
{
  AutoLock _l(m_mutex);

  char path[PATH_MAX];
  ABS_PATH(config_path, path, sizeof(path));
  m_path = path;

  File file;
  if (!config_path || !file.open(config_path, "r"))
    return -1;

  char line[MaxLine], *pline;
  char name[256], value[256], note[MaxLine] = {0}, type[256], def[256], range[256], *pdst;
  ConfigItem *item = NULL;
  while (file.read_line(line, sizeof(line))) {
    pline = skip_blank(line);
    if (*pline == '\0') continue;
    if (*pline == '#') {
      for (pdst = pline+strlen(pline)-1; pdst >= pline; --pdst)
        if (!isspace(*pdst)) break;
      pline[pdst-pline+1] = '\0';
      pline = skip_blank(pline+1);
      strncpy(note, pline, sizeof(note)); // note done
      continue;
    }
    for (pdst = name; *pline && !is_delime(pline); ++pline)
      *pdst++ = *pline;
    *pdst = '\0'; // name done
    while (*pline && is_delime(pline)) ++pline;
    for (pdst = value; *pline && !is_delime(pline); ++pline)
      *pdst++ = *pline;
    *pdst = '\0'; // value done
    if (value[0] == '\0') goto skip;
    type[0] = '\0'; def[0] = '\0'; range[0] = '\0';
    if (!(pdst = strchr(pline, '#'))) goto item_done;
    if (!(pline = strchr(pdst+1, '<'))) goto skip;
    for (pdst = type, ++pline; *pline && *pline != '>'; ++pline)
      *pdst++ = *pline;
    *pdst = '\0'; // type done
    if (!*pline) goto skip;
    if ((pline = strchr(pline+1, '['))) {
      for (pdst = def, ++pline; *pline && *pline != ']'; ++pline)
        *pdst++ = *pline;
      *pdst = '\0'; // def done
      if (!*pline) goto skip;
    }
    if (!strncasecmp(type, "INTEGER", 7) ||
        !strncasecmp(type, "ENUM", 4)) {
      if (!(pline = strchr(pline, '{'))) {
        if (toupper(type[0]) == 'I') goto item_done;
        else goto skip;
      }
      for (pdst = range, ++pline; *pline && *pline != '}'; ++pline)
        *pdst++ = *pline;
      *pdst = '\0'; // range done
      if (!*pline) goto skip;
    }
item_done:
    item = new ConfigItem(name, value,
                          type[0] ? type : NULL, def[0] ? def : NULL,
                          range[0] ? range : NULL, note[0] ? note : NULL);
    if (!item->is_valid()) goto skip;
    if (has_config(name)) {
      if (!m_cb_map.empty() &&
          m_reg.find(name) != m_reg.end() &&
          strcmp(m_map[name]->value, value)) {
        FOR_MAP(m_cb_map, ConfigUpdateCB, void *, it)
          (MAP_KEY(it))(name, value, MAP_VAL(it));
      }
      SAFE_DELETE(m_map[name]);
    }
    m_map[name] = item; item = NULL;
    note[0] = '\0';
    continue;
skip:
    LOGW("Invalid config item \"%s\"", name);
    SAFE_DELETE(item);
    note[0] = '\0';
  }

  file.close();
  return 0;
}

int ConfigImpl::start_monitor(volatile bool *watch_variable)
{
  assert(watch_variable);
  m_watch_variable = watch_variable;
  m_thrd = CREATE_THREAD_ROUTINE(monitor_routine, NULL, false);
  return 0;
}

int ConfigImpl::stop_monitor()
{
  *m_watch_variable = true;
  if (m_ctl[0] != -1) {
    const char str[] = "wakeup";
    send(m_ctl[0], str, sizeof(str), MSG_NOSIGNAL);
  }
  JOIN_DELETE_THREAD(m_thrd);
  return 0;
}

void *ConfigImpl::monitor_routine(void *arg)
{
#define EVENT_HEADER_SIZE   (sizeof(struct inotify_event))
  int fd = -1, wd = -1;
  fd_set rfd;
  struct timeval tv;
  char buff[BUFSIZ]
    __attribute__ ((aligned(__alignof__(EVENT_HEADER_SIZE))));
  int n;

  if ((fd = inotify_init1(IN_NONBLOCK)) < 0) {
    LOGE("inotify_fd() failed: %s", ERRNOMSG);
    goto out;
  }

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, m_ctl) < 0) {
    LOGE("socketpair failed for ctl: %s", ERRNOMSG);
  }

  while (!*m_watch_variable) {
    if (wd < 0) {
      AutoLock _l(m_mutex);

      if ((wd = inotify_add_watch(fd, STR(m_path),
                                  IN_IGNORED|IN_CLOSE_WRITE|IN_MOVE_SELF|IN_MOVE)) < 0) {
        LOGE("inotify_add_watch() failed: %s", ERRNOMSG);
        goto out;
      }
    }

    FD_ZERO(&rfd);
    FD_SET(fd, &rfd);
    if (m_ctl[1] != -1) FD_SET(m_ctl[1], &rfd);
    tv.tv_sec = 1; tv.tv_usec = 0;
    int ret = select(MAX(fd, m_ctl[1]) + 1, &rfd, NULL, NULL, &tv);
    if (ret == 0) continue;
    else if (ret < 0) {
      LOGE("select() failed: %s", ERRNOMSG);
      break;
    }

    if (*m_watch_variable)
      break;

    if (m_ctl[1] != -1 && FD_ISSET(m_ctl[1], &rfd)) {
      n = read(m_ctl[1], buff, sizeof(buff));
      break;
    }

    if (FD_ISSET(fd, &rfd)) {
      n = read(fd, buff, sizeof(buff));
      if (n < 0) {
        if (errno != EAGAIN) {
          LOGE("read() from inotify system failed: %s", ERRNOMSG);
          break;
        } else continue;
      }

      bool need_rm_wd = false;
      int off = 0;
      while (off < n) {
        const struct inotify_event *ev = (struct inotify_event *) &buff[off];
        if (ev->wd == wd) {
          //LOGD("ev->wd=%d, wd=%d, ev->mask=0x%0x", ev->wd, wd, ev->mask);
          if (ev->mask&IN_IGNORED) {
            need_rm_wd = true;
            break;
          } else {
            AutoLock _l(m_mutex);

            if (ev->mask&(IN_MOVE_SELF|IN_MOVE)) sync();
            if (load(STR(m_path)) < 0) {
              LOGE("load config \"%s\" failed", STR(m_path));
              goto out;
            }
            break;
          }
        }
        off += EVENT_HEADER_SIZE + ev->len;
      }
      if (need_rm_wd) wd = -1;
    }
  }

out:
  if (wd >= 0)
    inotify_rm_watch(fd, wd);
  SAFE_CLOSE(fd);
  return (void *) NULL;
}

Config *create_config(const char *config_path, volatile bool *watch_variable)
{
  ConfigImpl *impl = new ConfigImpl();
  if (impl->load(config_path) < 0) {
    LOGE("load config \"%s\" failed", config_path);
    goto bail;
  }
  impl->start_monitor(watch_variable);
  return impl;

bail:
  SAFE_DELETE(impl);
  return NULL;
}

void destroy_config(Config **config)
{
  ((ConfigImpl *) (*config))->stop_monitor();
  SAFE_DELETE(*config);
}

}
