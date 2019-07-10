#!/bin/bash

set -e

# Lucky number
export PYTHONHASHSEED=22

here="$(dirname "$(readlink -e "$0")")"
test -n "$here" -a -d "$here" || exit

export CONTRIB="$here/.."
export CACHEDIR="$here/.cache"
export PIP_CACHE_DIR="$CACHEDIR/pip_cache"

. "$CONTRIB"/build_tools_util.sh

info "Clearing $here/build and $here/dist..."
rm "$here"/build/* -rf
rm "$here"/dist/* -rf

mkdir -p "$CACHEDIR" "$PIP_CACHE_DIR"

$here/build-secp256k1.sh || fail "build-secp256k1 failed"

$here/prepare-wine.sh || fail "prepare-wine failed"

info "Resetting modification time in C:\Python..."
# (Because of some bugs in pyinstaller)
pushd /opt/wine64/drive_c/python*
find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd
ls -l /opt/wine64/drive_c/python*

$here/build-electrum-git.sh || fail "build-electrum-git failed"

info "Done."
