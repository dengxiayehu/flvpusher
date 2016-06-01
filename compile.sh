#! /usr/bin/env bash
# compile.sh

if [ -z "$MKFLAGS" ]; then
    UNAMES=$(uname -s)
    MKFLAGS=
    if which nproc >/dev/null; then
        export MKFLAGS=-j`nproc`
    elif [ "$UNAMES" == "Darwin" ] && which sysctl >/dev/null; then
        export MKFLAGS=-j`sysctl -n machdep.cpu.thread_count`
    fi
fi

bash contrib/compile-contrib.sh
bash sources/compile-flvpusher.sh
