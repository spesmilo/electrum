#!/bin/bash
# heavily based on https://github.com/ofek/coincurve/blob/417e726f553460f88d7edfa5dc67bfda397c4e4a/.travis/build_windows_wheels.sh

set -e

function fail {
    RED='\033[0;31m'
    printf "\r🗯 ${RED}ERROR:${NC} ${1}\n"
    exit 1
}

build_dll() {
    #sudo apt-get install -y mingw-w64
    export SOURCE_DATE_EPOCH=1530212462
    ./autogen.sh || fail "Could not run autogen.sh for secp256k1"
    echo "LDFLAGS = -no-undefined" >> Makefile.am
    LDFLAGS="-Wl,--no-insert-timestamp" ./configure \
        --host=$1 \
        --enable-module-recovery \
        --enable-experimental \
        --enable-module-ecdh \
        --with-bignum=no \
        --disable-jni || fail "Could not run ./configure for secp256k1"
    make -j4 || fail "Could not build secp256k1"
    ${1}-strip .libs/libsecp256k1-0.dll
}

pushd ../secp256k1 || fail "Could not chdir to secp256k1"
LIBSECP_VERSION="a1d5a30364d2ca8ed8bb3ef3dd345cc75708a8b2"  # According to Mark Blundeberg, using a commit hash guarantees no repository man-in-the-middle funny business as git is secure when verifying hashes.
git checkout $LIBSECP_VERSION || fail "Could not check out secp256k1 $LIBSECP_VERSION"
git clean -f -x -q

build_dll i686-w64-mingw32  # 64-bit would be: x86_64-w64-mingw32
mv .libs/libsecp256k1-0.dll libsecp256k1.dll || fail "Could not find generated DLL"

find -exec touch -d '2000-11-11T11:11:11+00:00' {} +

popd

echo "building libsecp256k1 finished"
