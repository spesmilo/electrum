#!/bin/bash

# This script can be used on Linux hosts to build native libzbar binaries.
# sudo apt-get install pkg-config libx11-dev libx11-6 libv4l-dev libxv-dev libxext-dev libjpeg-dev
#
# It can also be used to cross-compile to Windows:
# $ sudo apt-get install mingw-w64 mingw-w64-tools win-iconv-mingw-w64-dev
# For a Windows x86 (32-bit) target, run:
# $ GCC_TRIPLET_HOST="i686-w64-mingw32" BUILD_TYPE="wine" ./contrib/make_zbar.sh
# Or for a Windows x86_64 (64-bit) target, run:
# $ GCC_TRIPLET_HOST="x86_64-w64-mingw32" BUILD_TYPE="wine" ./contrib/make_zbar.sh

ZBAR_VERSION="d2893738411be897a04caa42ffc13d1f6107d3c6"

set -e

. $(dirname "$0")/build_tools_util.sh || (echo "Could not source build_tools_util.sh" && exit 1)

here=$(dirname $(realpath "$0" 2> /dev/null || grealpath "$0"))
CONTRIB="$here"
PROJECT_ROOT="$CONTRIB/.."

pkgname="zbar"
info "Building $pkgname..."

(
    cd $CONTRIB
    if [ ! -d zbar ]; then
        git clone https://github.com/mchehab/zbar.git
    fi
    cd zbar
    if ! $(git cat-file -e ${ZBAR_VERSION}) ; then
        info "Could not find requested version $ZBAR_VERSION in local clone; fetching..."
        git fetch --all
    fi
    git reset --hard
    git clean -dfxq
    git checkout "${ZBAR_VERSION}^{commit}"

    if [ "$BUILD_TYPE" = "wine" ] ; then
        echo "libzbar_la_LDFLAGS += -Wc,-static" >> zbar/Makefile.am
        echo "LDFLAGS += -Wc,-static" >> Makefile.am
    fi
    if ! [ -x configure ] ; then
        autoreconf -vfi || fail "Could not run autoreconf for $pkgname. Please make sure you have automake and libtool installed, and try again."
    fi
    if ! [ -r config.status ] ; then
        if [ "$BUILD_TYPE" = "wine" ] ; then
            # windows target
            ./configure \
                $AUTOCONF_FLAGS \
                --prefix="$here/$pkgname/dist" \
                --with-x=no \
                --enable-pthread=no \
                --enable-doc=no \
                --enable-video=yes \
                --with-directshow=yes \
                --with-jpeg=no \
                --with-python=no \
                --with-gtk=no \
                --with-qt=no \
                --with-java=no \
                --with-imagemagick=no \
                --with-dbus=no \
                --enable-codes=qrcode \
                --disable-dependency-tracking \
                --disable-static \
                --enable-shared || fail "Could not configure $pkgname. Please make sure you have a C compiler installed and try again."
        else
            # linux target
            ./configure \
                $AUTOCONF_FLAGS \
                --prefix="$here/$pkgname/dist" \
                --with-x=yes \
                --enable-pthread=no \
                --enable-doc=no \
                --enable-video=yes \
                --with-jpeg=yes \
                --with-python=no \
                --with-gtk=no \
                --with-qt=no \
                --with-java=no \
                --with-imagemagick=no \
                --with-dbus=no \
                --enable-codes=qrcode \
                --disable-static \
                --enable-shared || fail "Could not configure $pkgname. Please make sure you have a C compiler installed and try again."
        fi
    fi
    make -j4 || fail "Could not build $pkgname"
    make install || fail "Could not install $pkgname"
    . "$here/$pkgname/dist/lib/libzbar.la"
    host_strip "$here/$pkgname/dist/lib/$dlname"
    cp -fpv "$here/$pkgname/dist/lib/$dlname" "$PROJECT_ROOT/electrum_ltc" || fail "Could not copy the $pkgname binary to its destination"
    info "$dlname has been placed in the inner 'electrum_ltc' folder."
)
