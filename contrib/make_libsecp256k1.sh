#!/bin/bash

LIBSECP_VERSION="b408c6a8b287003d1ade5709e6f7bc3c7f1d5be7"

set -e

. $(dirname "$0")/build_tools_util.sh || (echo "Could not source build_tools_util.sh" && exit 1)

here=$(dirname $(realpath "$0" 2> /dev/null || grealpath "$0"))
CONTRIB="$here"
PROJECT_ROOT="$CONTRIB/.."

pkgname="secp256k1"
info "Building $pkgname..."

(
    cd $CONTRIB
    if [ ! -d secp256k1 ]; then
        git clone https://github.com/bitcoin-core/secp256k1.git
    fi
    cd secp256k1
    git reset --hard
    git clean -f -x -q
    git checkout $LIBSECP_VERSION

    if ! [ -x configure ] ; then
        echo "libsecp256k1_la_LDFLAGS = -no-undefined" >> Makefile.am
        echo "LDFLAGS = -no-undefined" >> Makefile.am
        ./autogen.sh || fail "Could not run autogen for $pkgname. Please make sure you have automake and libtool installed, and try again."
    fi
    if ! [ -r config.status ] ; then
        ./configure \
            $AUTOCONF_FLAGS \
            --prefix="$here/$pkgname/dist" \
            --enable-module-recovery \
            --enable-experimental \
            --enable-module-ecdh \
            --disable-jni \
            --disable-tests \
            --disable-static \
            --enable-shared || fail "Could not configure $pkgname. Please make sure you have a C compiler installed and try again."
    fi
    make -j4 || fail "Could not build $pkgname"
    make install || fail "Could not install $pkgname"
    . "$here/$pkgname/dist/lib/libsecp256k1.la"
    host_strip "$here/$pkgname/dist/lib/$dlname"
    cp -fpv "$here/$pkgname/dist/lib/$dlname" "$PROJECT_ROOT/electrum" || fail "Could not copy the $pkgname binary to its destination"
    info "$dlname has been placed in the inner 'electrum' folder."
)
