#! /usr/bin/env bash
# compile-contrib.sh

ABS_DIR="$(cd "$(dirname "$0")"; pwd)"

TARBALLS_DIR="$ABS_DIR/tarballs"
CONTRIB_SRC_DIR="$ABS_DIR/contrib-linux"
INSTALL_DIR="$ABS_DIR/install"

NO_OUTPUT="1>/dev/null 2>&1"

function exit_msg() {
    echo $@
    exit 1
}

TARS_HDLR_ARR=(
"zlib-1.2.8.tar.gz:compile_zlib"
"openssl-1.0.2g.tar.gz:compile_openssl"
"librtmp.tar.bz2:compile_librtmp"
)

[ ! -d "$TARBALLS_DIR" ] && { \
    echo "No tarballs dir found"; return 1; }
[ ! -d "$CONTRIB_SRC_DIR" ] && mkdir "$CONTRIB_SRC_DIR"

function compile_zlib() {
    CFLAGS="-fPIC" ./configure --const --static --64 --prefix="$INSTALL_DIR" &&
        make $MKFLAGS &&
        make install && return 0
    return 1
}

function compile_openssl() {
    ./Configure linux-x86_64 -fPIC threads zlib no-shared --prefix="$INSTALL_DIR" --with-zlib-lib="$INSTALL_DIR/lib" --with-zlib-include="$INSTALL_DIR/include" &&
        make depend &&
        make &&
        make install && return 0
    return 1
}

function compile_librtmp() {
    make $MKFLAGS \
         INC=-I"$INSTALL_DIR/include" XLDFLAGS="-L$INSTALL_DIR/lib" \
         prefix="$INSTALL_DIR" \
         install && return 0
    return 1
}

function extract() {
    local tar="$1" bn=`basename "$tar"`
    local dst_parent="$2"
    local tar_suffix_hdlr=(
            ".tar:tar_xvf_@_-C"
            ".tar.gz|.tgz:tar_zxvf_@_-C"
            ".tar.bz|.tar.bz2:tar_jxvf_@_-C"
            ".tar.Z:tar_Zxvf_@_-C"
            ".zip:unzip_-e_@_-d"
            )
    for tsh in ${tar_suffix_hdlr[@]}; do
        local suffix=`echo $tsh | cut -d: -f1`
        local suffix_arr=(${suffix//|/ })
        for sf in ${suffix_arr[@]}; do
            local fm=`echo $bn | sed -n "s/\(.*\)$sf$/\1/p"`
            [ -z "$fm" ] && continue
            local dstsrc="$dst_parent/$fm"
            [ -d  "$dstsrc" ] && \
                { echo "$dstsrc" && return 0; }
            local hdlr=`echo $tsh | cut -d: -f2 | tr -s '_' ' ' | sed -n 's/ @ / $tar /p'`" $dst_parent"
            eval "$hdlr $NO_OUTPUT" || \
                { echo "" && return 1; }
            echo "$dstsrc"
            return 0
        done
    done
}

function compile() {
    local tar="$1"
    local hdlr="$2"
    local dstsrc=`extract "$tar" "$CONTRIB_SRC_DIR"`
    [ -n "$dstsrc" ] || \
        exit_msg "extract \"$tar\" failed"
    cd "$dstsrc"
    local stamp=".stamp"
    [ -f "$stamp" ] && return 0
    $hdlr || \
        exit_msg "compile `basename $tar` failed"
    cd "$dstsrc"
    touch "$stamp"
}

for th in ${TARS_HDLR_ARR[@]}; do
    tar="$TARBALLS_DIR/`echo "$th" | cut -d: -f1`"
    hdlr=`echo "$th" | cut -d: -f2`
    echo "----------------------------"
    echo "[*] $hdlr"
    echo "----------------------------"
    compile "$tar"  "$hdlr"
    echo -e "Done\n"
done

exit 0
