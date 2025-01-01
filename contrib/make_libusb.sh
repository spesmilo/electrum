#!/bin/bash

LIBUSB_VERSION="4239bc3a50014b8e6a5a2a59df1fff3b7469543b"
# ^ tag v1.0.26

set -e

. $(dirname "$0")/build_tools_util.sh || (echo "Could not source build_tools_util.sh" && exit 1)

here="$(dirname "$(realpath "$0" 2> /dev/null || grealpath "$0")")"
CONTRIB="$here"
PROJECT_ROOT="$CONTRIB/.."

pkgname="libusb"
info "Building $pkgname..."

(
    cd "$CONTRIB"
    if [ ! -d libusb ]; then
        git clone https://github.com/libusb/libusb.git
    fi
    cd libusb
    if ! $(git cat-file -e ${LIBUSB_VERSION}) ; then
        info "Could not find requested version $LIBUSB_VERSION in local clone; fetching..."
        git fetch --all
    fi
    git reset --hard
    git clean -dfxq
    git checkout "${LIBUSB_VERSION}^{commit}"

    if [ "$BUILD_TYPE" = "wine" ] ; then
        echo "libusb_1_0_la_LDFLAGS += -Wc,-static" >> libusb/Makefile.am
    fi
    ./bootstrap.sh || fail "Could not bootstrap libusb"
    if ! [ -r config.status ] ; then
        if [ "$BUILD_TYPE" = "wine" ] ; then
            # windows target
            LDFLAGS="-Wl,--no-insert-timestamp"
        elif [ $(uname) == "Darwin" ]; then
            # macos target
            LDFLAGS="-Wl -lm"
        else
            # linux target
            LDFLAGS=""
        fi
        LDFLAGS="$LDFLAGS" ./configure \
            $AUTOCONF_FLAGS \
            || fail "Could not configure $pkgname. Please make sure you have a C compiler installed and try again."
    fi
    make "-j$CPU_COUNT" || fail "Could not build $pkgname"
    make install || warn "Could not install $pkgname"
    . "$here/$pkgname/libusb/.libs/libusb-1.0.la"
    host_strip "$here/$pkgname/libusb/.libs/$dlname"
    TARGET_NAME="$dlname"
    if [ $(uname) == "Darwin" ]; then  # on mac, dlname is "libusb-1.0.0.dylib"
        TARGET_NAME="libusb-1.0.dylib"
    fi
    cp -fpv "$here/$pkgname/libusb/.libs/$dlname" "$PROJECT_ROOT/electrum/$TARGET_NAME" || fail "Could not copy the $pkgname binary to its destination"
    info "$TARGET_NAME has been placed in the inner 'electrum' folder."
    if [ -n "$DLL_TARGET_DIR" ] ; then
        cp -fpv "$here/$pkgname/libusb/.libs/$dlname" "$DLL_TARGET_DIR/$TARGET_NAME" || fail "Could not copy the $pkgname binary to DLL_TARGET_DIR"
    fi
)
