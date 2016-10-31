#include "talk/examples/peerconnection/direct/defaults.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "webrtc/base/common.h"

const char kAudioLabel[] = "dxyh_audio";
const char kVideoLabel[] = "dxyh_video";
const char kStreamLabel[] = "dxyh_stream";
const uint16 kDefaultServerPort = 8888;

std::string GetEnvVarOrDefault(const char *env_var_name,
                               const char *default_value) {
  std::string value;
  const char* env_var = getenv(env_var_name);
  if (env_var)
  value = env_var;

  if (value.empty())
  value = default_value;

  return value;
}

std::string GetPeerConnectionString() {
  //return GetEnvVarOrDefault("WEBRTC_CONNECT", "stun:stun.l.google.com:19302");
  return GetEnvVarOrDefault("WEBRTC_CONNECT", "stun:192.168.6.39:1234");
}

std::string GetPeerName() {
  char computer_name[256];
  if (gethostname(computer_name, ARRAY_SIZE(computer_name)) != 0)
    strcpy(computer_name, "host");
  std::string ret(GetEnvVarOrDefault("USERNAME", "dengxiayehu"));
  ret += '@';
  ret += computer_name;
  return ret;
}
