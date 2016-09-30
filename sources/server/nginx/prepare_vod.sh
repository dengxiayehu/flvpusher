#!/bin/bash
# prepare_vod.sh
# prepare for flvpusher's dynamic vod
# usage: prepare_vod.sh <input media-file|directory> <webserver's-root-dir> [flvpusher-tool-path] [hls-time] [result.txt]

# ------- global -------
# Current dir's absolute path
ABS_DIR="$(cd $(dirname $0); pwd)"

# Tool flvpusher path, version >= 20160928.0.1
flvpusher="$ABS_DIR/flvpusher"

# Our label following webserver's root dir in path
LABEL="hls-dynamic-vod"

# ------- functions -------
function err_quit() {
  echo -e "\033[31;1m"$@"\033[0m" >&2
  exit 1
}

# Get filename's extension, note: in lower case
function file_ext() {
  echo ${1##*.} | tr "A-Z" "a-z"
}

# Get filename's main part
function file_main() {
  local file=`basename "$1"`
  echo ${file%.*}
}

# Convert relative path to absolute path
function realpath() {
  local path="$1"
  [ "${path:0:1}" = "/" ] || \
    path="$(cd $(dirname $path); pwd)/`basename $path`"
  echo "$path"
}

# prepare file for hls dynamic vod
function prepare_file() {
  local input="$1"
  local dst_m3u8="$html_root/$LABEL/`dirname $input`/`file_main $input`/va.m3u8"
  local html_root="$2"
  local flvpusher="$3"
  local hls_time="$4"

  mkdir -p `dirname "$dst_m3u8"` || \
    err_quit "mkdir \"$dst_m3u8\" failed"

  "$flvpusher" -i "$input" \
    --hls_playlist "$dst_m3u8" --hls_time "$hls_time" \
    -l `dirname "$dst_m3u8"`/flvpusher.log
  if [ $? -eq 0 ]; then
    echo "$input:$dst_m3u8"
    return 0
  else
    echo "$input:ERROR"
    return 1
  fi
}

trap 'sigint_handler' SIGINT
quit=0
      
function sigint_handler() { 
  quit=1
}

function scan_dir() {
  local dir="$1"
  local res

  for f in `ls "$dir"`; do
    [ $quit -ne 0 ] && \
      return 0

    f="$dir/$f"
    if [ -f "$f" ]; then
      local f_ext=`file_ext "$f"`
      [ "$f_ext" = "3gp" -o "$f_ext" = "mp4" -o "$f_ext" = "flv" ] && \
        res=`prepare_file "$f" "$html_root" "$flvpusher" "$hls_time"`
      [ -n "$result_file" ] && \
        echo "$res" >> "$result_file"
    elif [ -d "$f" ]; then
      scan_dir "$f"
    fi
  done
}

# ------- main starts here -------
# check the params
[ $# -lt 2 ] && \
  err_quit "usage: prepare_vod.sh <input media-file|directory> <webserver's-root-dir> [flvpusher-tool-path] [hls-time] [result.txt]"

input=`realpath "$1"`
html_root=`realpath "$2"`
flvpusher="$ABS_DIR/flvpusher"
if [ $# -gt 2 ]; then
  flvpusher=`realpath "$3"`
fi
hls_time=5
if [ $# -gt 3 ]; then
  hls_time="$4"
fi
result_file=""
if [ $# -gt 4 ]; then
  result_file="$5"
fi
if [ -n "$result_file" ]; then
  [ -f "$result_file" ] && \
    mv "$result_file" "${result_file}.bak"
  : > "$result_file"
fi

is_input_file=0
input_ext=`file_ext "$input"`
if [ "$input_ext" = "3gp" -o "$input_ext" = "mp4" -o "$input_ext" = "flv" ]; then
  [ ! -f "$input" ] && \
    err_quit "input file \"$input\" not exists"
  is_input_file=1
else
  [ ! -d "$input" ] && \
    err_quit "input dir \"$input\" not exists"
fi

[ ! -d "$html_root" ] && \
  err_quit "webserver's root dir \"$html_root\" not exists"

[ ! -f "$flvpusher" ] && \
  err_quit "flvpusher \"$flvpusher\" not exists"
# Make it executable
chmod a+x "$flvpusher"

[ $hls_time -le 0 ] && \
  err_quit "hls_time \"$hls_time\" is invalid"

if [ $is_input_file -eq 1 ]; then
  res=`prepare_file "$input" "$html_root" "$flvpusher" "$hls_time"`
  ret="$?"
  [ -n "$result_file" ] && \
    echo "$res" >> "$result_file"
  exit $ret
fi

# We need to scan the specified dir for 3gp|mp4|flv files
scan_dir "$input"
exit 0
