#ifndef TALK_EXAMPLES_PEERCONNECTION_DIRECT_FLAGDEFS_H_
#define TALK_EXAMPLES_PEERCONNECTION_DIRECT_FLAGDEFS_H_
#pragma once

#include "webrtc/base/flags.h"

extern const uint16 kDefaultServerPort;

DEFINE_bool(help, false, "Print this message [dengxiayehu@yeah.net]");
DEFINE_string(server, "192.168.119.1", "The server to connect to.");
DEFINE_int(port, kDefaultServerPort,
           "The port on which the server is listening.");

#endif // TALK_EXAMPLES_PEERCONNECTION_DIRECT_FLAGDEFS_H_
