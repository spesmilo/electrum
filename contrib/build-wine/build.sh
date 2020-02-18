#!/bin/bash

set -e

here="$(dirname "$(readlink -e "$0")")"
test -n "$here" -a -d "$here" || exit

export CONTRIB="$here/.."
export PROJECT_ROOT="$CONTRIB/.."
export CACHEDIR="$here/.cache"
export PIP_CACHE_DIR="$CACHEDIR/pip_cache"

export BUILD_TYPE="wine"
export GCC_TRIPLET_HOST="i686-w64-mingw32"
export GCC_TRIPLET_BUILD="x86_64-pc-linux-gnu"
export GCC_STRIP_BINARIES="1"

. "$CONTRIB"/build_tools_util.sh

info "Clearing $here/build and $here/dist..."
rm "$here"/build/* -rf
rm "$here"/dist/* -rf

mkdir -p "$CACHEDIR" "$PIP_CACHE_DIR"

if [ -f "$PROJECT_ROOT/electrum/libsecp256k1-0.dll" ]; then
    info "libsecp256k1 already built, skipping"
else
    "$CONTRIB"/make_libsecp256k1.sh || fail "Could not build libsecp"
fi

$here/prepare-wine.sh || fail "prepare-wine failed"

info "Resetting modification time in C:\Python..."
# (Because of some bugs in pyinstaller)
pushd /opt/wine64/drive_c/python*
find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd
ls -l /opt/wine64/drive_c/python*

$here/build-electrum-git.sh || fail "build-electrum-git failed"

info "Done."
