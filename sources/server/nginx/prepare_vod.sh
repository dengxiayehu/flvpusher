#!/bin/bash
# prepare_vod.sh
# prepare for flvpusher's dynamic vod with input mp4|flv file
# usage: prepare_vod.sh <webserver's root dir> <input mp4|flv> [flvpusher tool path]

ABS_DIR="$(cd "$(dirname "$0")"; pwd)"

if [ $# -lt 2 ]; then
  echo "usage: prepare_vod.sh <webserver's root dir> <input mp4|flv> [flvpusher tool path]"
  exit 1
fi

html_root="$1"
input_file="$2"
flvpusher="$ABS_DIR/flvpusher"
if [ $# -gt 2 ]; then
  flvpusher="$3"
fi
# check params
if [ ! -d "$html_root" -o ! -f "$input_file" -o ! -x "$flvpusher" ]; then
  echo "invalid parameters detected" >&2
  exit 1
fi

# determine the output m3u8_path, hls_info.txt xxx.m3u8.seek are
# also generated in the same directory
input_file_basename=`basename "$input_file"`
input_filename_main_part=${input_file_basename%.*}
m3u8_path="$html_root/hls-dynamic-vod/"`date '+%Y/%m/%d'`"/$input_filename_main_part/$input_filename_main_part.m3u8"
if [ -f "$m3u8_path" ]; then
  echo "WARNING! \"$m3u8_path\" already exists"
  rm -rf "$m3u8_path"
fi

"$flvpusher" -i "$input_file" --hls_playlist "$m3u8_path"
exit $?
