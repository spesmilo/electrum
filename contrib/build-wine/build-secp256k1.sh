#!/bin/bash
# heavily based on https://github.com/ofek/coincurve/blob/417e726f553460f88d7edfa5dc67bfda397c4e4a/.travis/build_windows_wheels.sh

set -e

here="$(dirname "$(readlink -e "$0")")"
LIBSECP_VERSION="b408c6a8b287003d1ade5709e6f7bc3c7f1d5be7"

. "$CONTRIB"/build_tools_util.sh

info "building libsecp256k1..."


build_dll() {
    #sudo apt-get install -y mingw-w64
    export SOURCE_DATE_EPOCH=1530212462
    ./autogen.sh
    echo "LDFLAGS = -no-undefined" >> Makefile.am
    LDFLAGS="-Wl,--no-insert-timestamp" ./configure \
        --host=$1 \
        --enable-module-recovery \
        --enable-experimental \
        --enable-module-ecdh \
        --disable-jni
    make -j4
    ${1}-strip .libs/libsecp256k1-0.dll
}


cd "$CACHEDIR"

if [ -f "secp256k1/libsecp256k1.dll" ]; then
    info "libsecp256k1.dll already built, skipping"
    exit 0
fi


if [ ! -d secp256k1 ]; then
    git clone https://github.com/bitcoin-core/secp256k1.git
fi

cd secp256k1
git reset --hard
git clean -f -x -q
git checkout $LIBSECP_VERSION

build_dll i686-w64-mingw32  # 64-bit would be: x86_64-w64-mingw32
mv .libs/libsecp256k1-0.dll libsecp256k1.dll

find -exec touch -d '2000-11-11T11:11:11+00:00' {} +

info "building libsecp256k1 finished"
