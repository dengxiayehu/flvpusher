#ifndef PEERCONNECTION_SAMPLES_DIRECT_DEFAULTS_H_
#define PEERCONNECTION_SAMPLES_DIRECT_DEFAULTS_H_
#pragma once

#include <string>

#include "webrtc/base/basictypes.h"

extern const char kAudioLabel[];
extern const char kVideoLabel[];
extern const char kStreamLabel[];
extern const uint16 kDefaultServerPort;

std::string GetPeerName();
std::string GetPeerConnectionString();

#endif // PEERCONNECTION_SAMPLES_DIRECT_DEFAULTS_H_
