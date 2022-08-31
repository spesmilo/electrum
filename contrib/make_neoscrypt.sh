#!/bin/bash

# This script was tested on Linux and MacOS hosts, where it can be used
# to build native neoscrypt binaries.
#
# It can also be used to cross-compile to Windows:
# $ sudo apt-get install mingw-w64
# For a Windows x86 (32-bit) target, run:
# $ GCC_TRIPLET_HOST="i686-w64-mingw32" ./contrib/make_neoscrypt.sh
# Or for a Windows x86_64 (64-bit) target, run:
# $ GCC_TRIPLET_HOST="x86_64-w64-mingw32" ./contrib/make_neoscrypt.sh
#
# To cross-compile to Linux x86:
# sudo apt-get install gcc-multilib g++-multilib
# $ AUTOCONF_FLAGS="--host=i686-linux-gnu CFLAGS=-m32 CXXFLAGS=-m32 LDFLAGS=-m32" ./contrib/make_neoscrypt.sh

LIBSECP_VERSION="dbd41db16a0e91b2566820898a3ab2d7dad4fe00"

set -e

. $(dirname "$0")/build_tools_util.sh || (echo "Could not source build_tools_util.sh" && exit 1)

here=$(dirname $(realpath "$0" 2> /dev/null || grealpath "$0"))
CONTRIB="$here"
PROJECT_ROOT="$CONTRIB/.."

pkgname="neoscrypt_module"
info "Building $pkgname..."

(
    cd "$CONTRIB/$pkgname"
   

    if ! [ -x configure ] ; then
        echo "neoscrypt_la_LDFLAGS = -no-undefined -L/usr/lib/x86_64-linux-gnu/" >> Makefile.am
        echo "LDFLAGS = -no-undefined " >> Makefile.am
 
        ./autogen.sh || fail "Could not run autogen for $pkgname. Please make sure you have automake and libtool installed, and try again."
    fi
    if ! [ -r config.status ] ; then
        ./configure \
            $AUTOCONF_FLAGS \
            --prefix="$here/$pkgname/dist" \
	    --with-gmp=no \
            --disable-static \
            --enable-shared || fail "Could not configure $pkgname. Please make sure you have a C compiler installed and try again."
    fi
    info "\nhere $here\n"
    make -j4 || fail "Could not build $pkgname"
    make install || fail "Could not install $pkgname"
    . "$here/$pkgname/libneoscrypt.la"
    #host_strip "$here/$pkgname/dist/lib/$dlname"
    cp -fpv "$here/$pkgname/dist/lib/$dlname" "$PROJECT_ROOT/electrum" || fail "Could not copy the $pkgname binary to its destination"
    info "$dlname has been placed in the inner 'electrum' folder."
    if [ -n "$DLL_TARGET_DIR" ] ; then
        cp -fpv "$here/$pkgname/dist/lib/$dlname" "$DLL_TARGET_DIR" || fail "Could not copy the $pkgname binary to DLL_TARGET_DIR"
    fi
)
