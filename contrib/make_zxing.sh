#!/usr/bin/env bash

# Build the QR decoder and C API for Linux, macOS, and Windows (using MinGW).
# Requires CMake and a C++20 compiler. Android builds use the libzxing p4a recipe.
# To cross-compile for Windows:
# $ GCC_TRIPLET_HOST=x86_64-w64-mingw32 BUILD_TYPE=wine ./contrib/make_zxing.sh

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
build_dir="$source_dir/build-$BUILD_TYPE${GCC_TRIPLET_HOST:+-$GCC_TRIPLET_HOST}"

cmake_flags=()
case "$BUILD_TYPE" in
    linux) library="libZXing.so" ;;
    darwin) library="libZXing.dylib" ;;
    wine)
        library="ZXing.dll"
        cmake_flags+=(
            -DCMAKE_SYSTEM_NAME=Windows
            "-DCMAKE_C_COMPILER=$GCC_TRIPLET_HOST-gcc"
            "-DCMAKE_CXX_COMPILER=$GCC_TRIPLET_HOST-g++"
            "-DCMAKE_RC_COMPILER=$GCC_TRIPLET_HOST-windres"
            # Bundle compiler runtimes and omit the PE timestamp for reproducibility.
            "-DCMAKE_SHARED_LINKER_FLAGS=-static -static-libgcc -static-libstdc++ -Wl,--no-insert-timestamp"
        )
        ;;
    *) fail "Unsupported native build type: $BUILD_TYPE" ;;
esac

mkdir -p "$cache_dir"
download_if_not_exist "$archive" "https://github.com/zxing-cpp/zxing-cpp/archive/$ZXING_VERSION.tar.gz"
verify_hash "$archive" "$ZXING_SHA256"
if [ ! -d "$source_dir" ]; then
    tar -xzf "$archive" -C "$cache_dir"
fi

# CMake caches absolute paths and compilers, which differ between local and Docker builds.
# Release scripts cache the finished library in DLL_TARGET_DIR instead.
rm -rf "$build_dir"

# Build core directly: the top-level C API target also pulls in test dependencies.
cmake -S "$source_dir/core" -B "$build_dir" \
    "${cmake_flags[@]}" \
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
# MinGW adds a lib prefix, whereas the ctypes loader uses the MSVC-style name.
if [ "$BUILD_TYPE" = "wine" ]; then
    cp -fv "$build_dir/libZXing.dll" "$build_dir/$library"
fi
host_strip "$build_dir/$library"
cp -Lfv "$build_dir/$library" "$PROJECT_ROOT/electrum/$library"
info "$library has been placed in the inner electrum folder."
if [ -n "$DLL_TARGET_DIR" ]; then
    cp -Lfv "$build_dir/$library" "$DLL_TARGET_DIR/$library"
fi
