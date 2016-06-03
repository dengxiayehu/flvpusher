cmake_minimum_required(VERSION 2.6)

SET(MODULE_NAME flvpusher)

PROJECT(${MODULE_NAME})

ADD_DEFINITIONS(-ggdb3 -O0 -Wall -Werror)

INCLUDE_DIRECTORIES(
	xutil
	${CMAKE_CURRENT_SOURCE_DIR}/../contrib/install/include
)

LINK_DIRECTORIES(
	${CMAKE_CURRENT_SOURCE_DIR}/../contrib/install/lib
)

FILE(GLOB SOURCES "*.cpp" "xutil/*.cpp")

SET(DEPEND_MODULES pthread dl libssl.a libcrypto.a libz.a libcurl.a librtmp.a dl rt libmongoose.a)

ADD_EXECUTABLE(${MODULE_NAME} ${SOURCES})
TARGET_LINK_LIBRARIES(${MODULE_NAME} ${DEPEND_MODULES})
