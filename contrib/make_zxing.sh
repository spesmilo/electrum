#!/usr/bin/env bash

# Build the QR decoder and C API for local testing (Linux/macOS).
# Requires CMake and a C++20 compiler. Android builds use the libzxing p4a recipe.
# This does not change the desktop scanner's default decoder (zbar).

set -e
. "$(dirname "$0")/build_tools_util.sh"

# zxing-cpp v3.1.1. Keep in sync with android/p4a_recipes/libzxing/__init__.py.
ZXING_VERSION="287c85df6f961c8efbfb5ffd736cd9457b8b890e"
ZXING_SHA256="97d952c661b1f79d21aacc2ec544ef05c4d1465f55692cc49622ea6a8166ca7b"

CONTRIB="$(dirname "$(realpath "$0")")"
PROJECT_ROOT="$CONTRIB/.."
cache_dir="$CONTRIB/.cache/zxing"
archive="$cache_dir/zxing-$ZXING_VERSION.tar.gz"
source_dir="$cache_dir/zxing-cpp-$ZXING_VERSION"
build_dir="$source_dir/build-native"

case "$BUILD_TYPE" in
    linux) library="libZXing.so" ;;
    darwin) library="libZXing.dylib" ;;
    *) fail "Unsupported native build type: $BUILD_TYPE" ;;
esac

mkdir -p "$cache_dir"
download_if_not_exist "$archive" "https://github.com/zxing-cpp/zxing-cpp/archive/$ZXING_VERSION.tar.gz"
verify_hash "$archive" "$ZXING_SHA256"
if [ ! -d "$source_dir" ]; then
    tar -xzf "$archive" -C "$cache_dir"
fi

# Build core directly: the top-level C API target also pulls in test dependencies.
cmake -S "$source_dir/core" -B "$build_dir" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_SKIP_RPATH=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DZXING_C_API=ON \
    -DZXING_READERS=ON \
    -DZXING_WRITERS=OFF \
    -DZXING_ENABLE_1D=OFF \
    -DZXING_ENABLE_AZTEC=OFF \
    -DZXING_ENABLE_DATAMATRIX=OFF \
    -DZXING_ENABLE_MAXICODE=OFF \
    -DZXING_ENABLE_PDF417=OFF \
    -DZXING_ENABLE_QRCODE=ON
cmake --build "$build_dir" --parallel "$CPU_COUNT"
host_strip "$build_dir/$library"
cp -Lfv "$build_dir/$library" "$PROJECT_ROOT/electrum/$library"
info "$library has been placed in the inner electrum folder."
