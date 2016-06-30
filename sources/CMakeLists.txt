cmake_minimum_required(VERSION 2.6)

SET(MODULE_NAME flvpusher)

PROJECT(${MODULE_NAME})

ADD_DEFINITIONS(-ggdb3 -O0 -Wall -Wno-unused-but-set-variable)

INCLUDE_DIRECTORIES(
	xutil
	${CMAKE_CURRENT_SOURCE_DIR}/../contrib/install/include
)

LINK_DIRECTORIES(
	${CMAKE_CURRENT_SOURCE_DIR}/../contrib/install/lib
)

FILE(GLOB SOURCES "*.cpp" "xutil/*.cpp")

SET(DEPEND_MODULES pthread librtmp.a libcurl.a libmongoose.a libssl.a libcrypto.a libz.a dl rt)

ADD_EXECUTABLE(${MODULE_NAME} ${SOURCES})
TARGET_LINK_LIBRARIES(${MODULE_NAME} ${DEPEND_MODULES})
