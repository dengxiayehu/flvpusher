#! /usr/bin/env bash
# compile-flvpusher.sh

ABS_DIR="$(cd "$(dirname "$0")"; pwd)"

[ ! -d "$ABS_DIR/build" ] && mkdir "$ABS_DIR/build"
cd "$ABS_DIR/build"

cmake .. && make && exit 0

exit 1
