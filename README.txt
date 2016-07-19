README for the flvpusher
===============================
A tool for pushing flv/mp4/ts/rtmp/rtsp/hls source to rtmp/rtspserver.
Compile it on a Linux operating system.

Compile
====================
./compile.sh

Run
====================
flvpusher (V: 2)

Usage: flvpusher <-i source|-w> <-L liveurl [--loop] [-a dump_audio] [-v dump_video] [-s tspath] [-f flvpath]|--hls_playlist filename [--hls_time time]> [-h] [--no_logfile]
Description: 
-i, --input
       input source, file category: *.flv, *.mp4, *.3gp, *.ts
                     protocol category: rtmp://*, rtsp://*, http://*.m3u8
-L, --live
       liveurl, inject audio&video to rtmp-server or rtsp-server,
       format: rtmp://<ip>[:port]/live/<rtmp-stream-name>
               rtsp://<ip>[:port]/<rtsp-sdp-name>.sdp
       note: this option is exclusive with -p and -w
-p, --hls_playlist
       pre-process flv or mp4 file to generate *.m3u8, *.m3u8.seek and hls_info.txt for dynamic hls vod
       note: this option is exclusive with -L and -w
-t, --hls_time
       specify the ts-segment's duration in hls vod
-w, --webserver
       start webserver
       note: this option is exclusive with -L and -p
-T, --loop
       if input source is done, start it over again
-N, --no_logfile
       do NOT generate log file, run this program in slience
-v, --dvfile
       dump raw video into file (format: H.264)
-a, --dafile
       dump raw audio into file (format: AAC)
-f, --flvpath
       dump video&audio into flv
-s, --tspath
       dump video&audio into ts
-h, --help
       show this help message and quit


Sample:
1. stream mp4 to rtmpserver (other input sources are the same)
$ flvpusher -i ~/Video/omn.mp4 -L rtmp://127.0.0.1:1935/live/va

2. stream mp4 to rtspserver (ditto)
$ flvpusher -i ~/Video/omn.mp4 -L rtsp://192.168.119.1/va.sdp

3. pre-process mp4 to prepare for hls dynamic vod
$ flvpusher -i ~/Video/omn.mp4 --hls_playlist html/omn/omn.m3u8 --hls_time 5

4. start webserver for hls vod
$ flvpusher -w
note: a. webserver server's root directory is default to ./html
      b. webserver server's port is default to 9877
      c. use player(e.g. vlc) to play this hls vod: http://<this-server-ip:9877>/omn/omn.m3u8
      d. you can modify root directory and listen port in flvpusher_cfg.txt, and put it in the same
         directory with this tool

Other
====================
Any further information please contact me.
mail: dengxiayehu@yeah.net
QQ: 947980562
