#!/bin/bash

set -e

here="$(dirname "$(readlink -e "$0")")"
test -n "$here" -a -d "$here" || exit

if [ -z "$WIN_ARCH" ] ; then
    export WIN_ARCH="win32"  # default
fi
if [ "$WIN_ARCH" = "win32" ] ; then
    export GCC_TRIPLET_HOST="i686-w64-mingw32"
elif [ "$WIN_ARCH" = "win64" ] ; then
    export GCC_TRIPLET_HOST="x86_64-w64-mingw32"
else
    echo "unexpected WIN_ARCH: $WIN_ARCH"
    exit 1
fi

export BUILD_TYPE="wine"
export GCC_TRIPLET_BUILD="x86_64-pc-linux-gnu"
export GCC_STRIP_BINARIES="1"

export CONTRIB="$here/.."
export PROJECT_ROOT="$CONTRIB/.."
export CACHEDIR="$here/.cache/$WIN_ARCH"
export PIP_CACHE_DIR="$CACHEDIR/wine_pip_cache"
export WINE_PIP_CACHE_DIR="c:/electrum/contrib/build-wine/.cache/$WIN_ARCH/wine_pip_cache"
export DLL_TARGET_DIR="$CACHEDIR/dlls"

export WINEPREFIX="/opt/wine64"
export WINEDEBUG=-all
export WINE_PYHOME="c:/python3"
export WINE_PYTHON="wine $WINE_PYHOME/python.exe -OO -B"

. "$CONTRIB"/build_tools_util.sh

info "Clearing $here/build and $here/dist..."
rm "$here"/build/* -rf
rm "$here"/dist/* -rf

mkdir -p "$CACHEDIR" "$DLL_TARGET_DIR" "$PIP_CACHE_DIR"

if [ -f "$DLL_TARGET_DIR/libsecp256k1-0.dll" ]; then
    info "libsecp256k1 already built, skipping"
else
    "$CONTRIB"/make_libsecp256k1.sh || fail "Could not build libsecp"
fi

if [ -f "$DLL_TARGET_DIR/libzbar-0.dll" ]; then
    info "libzbar already built, skipping"
else
    "$CONTRIB"/make_zbar.sh || fail "Could not build zbar"
fi

if [ -f "$DLL_TARGET_DIR/libusb-1.0.dll" ]; then
    info "libusb already built, skipping"
else
    "$CONTRIB"/make_libusb.sh || fail "Could not build libusb"
fi

"$here/prepare-wine.sh" || fail "prepare-wine failed"

info "Resetting modification time in C:\Python..."
# (Because of some bugs in pyinstaller)
pushd /opt/wine64/drive_c/python*
find -exec touch -h -d '2000-11-11T11:11:11+00:00' {} +
popd
ls -l /opt/wine64/drive_c/python*

"$here/build-electrum-git.sh" || fail "build-electrum-git failed"

info "Done."
