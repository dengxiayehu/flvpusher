cmake_minimum_required(VERSION 2.6)

SET(PROG_NAME flvpusher)

PROJECT(${PROG_NAME})

ADD_DEFINITIONS(-ggdb3 -O0 -Wall -Wno-unused-but-set-variable)

SET(MODULE_LIST app common flv hls mp4 ts rtmp rtsp server xutil .)

INCLUDE_DIRECTORIES(
	.
	xutil
	${CMAKE_CURRENT_SOURCE_DIR}/../contrib/install/include
)

LINK_DIRECTORIES(
	${CMAKE_CURRENT_SOURCE_DIR}/../contrib/install/lib
)

UNSET(SOURCES)
FOREACH(M ${MODULE_LIST})
	AUX_SOURCE_DIRECTORY(${M} SOURCES)
ENDFOREACH(M)

SET(DEPEND_MODULES pthread librtmp.a libcurl.a libmongoose.a libssl.a libcrypto.a libz.a dl rt)

ADD_EXECUTABLE(${PROG_NAME} ${SOURCES})
TARGET_LINK_LIBRARIES(${PROG_NAME} ${DEPEND_MODULES})
