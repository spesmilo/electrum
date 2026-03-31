#!/bin/bash

set -e

here="$(dirname "$(readlink -e "$0")")"
test -n "$here" -a -d "$here" || exit

if [ -z "$WIN_ARCH" ] ; then
    export WIN_ARCH="win64"  # default
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
export CACHEDIR="$here/.cache/$WIN_ARCH/build"
export PIP_CACHE_DIR="$here/.cache/$WIN_ARCH/wine_pip_cache"
export WINE_PIP_CACHE_DIR="c:/electrum/contrib/build-wine/.cache/$WIN_ARCH/wine_pip_cache"
export DLL_TARGET_DIR="$CACHEDIR/dlls"

export WINEPREFIX="/opt/wine64"
export WINEDEBUG=-all
export WINE_PYHOME="c:/python3"
export WINE_PYTHON="wine $WINE_PYHOME/python.exe -B"

. "$CONTRIB"/build_tools_util.sh

git -C "$PROJECT_ROOT" rev-parse 2>/dev/null || fail "Building outside a git clone is not supported."

info "Clearing $here/build and $here/dist..."
rm "$here"/build/* -rf
rm "$here"/dist/* -rf

mkdir -p "$CACHEDIR" "$DLL_TARGET_DIR" "$PIP_CACHE_DIR"

if ls "$DLL_TARGET_DIR"/libsecp256k1-*.dll 1> /dev/null 2>&1; then
    info "libsecp256k1 already built, skipping"
else
    "$CONTRIB"/make_libsecp256k1.sh || fail "Could not build libsecp"
fi

if [ -f "$DLL_TARGET_DIR/libzbar-0.dll" ]; then
    info "libzbar already built, skipping"
else
    (
        # iconv is needed for zbar. see https://github.com/mchehab/zbar/blob/a549566ea11eb03622bd4458a1728ffe3f589163/README-windows.md
        # (previously were using win-iconv, but changed to GNU libiconv due to compilation errors with modern gcc)
        LIBICONV_VER="1.18"
        download_if_not_exist "$CACHEDIR/libiconv-${LIBICONV_VER}.tar.gz" "https://ftp.gnu.org/pub/gnu/libiconv/libiconv-${LIBICONV_VER}.tar.gz"
        verify_hash "$CACHEDIR/libiconv-${LIBICONV_VER}.tar.gz" "3b08f5f4f9b4eb82f151a7040bfd6fe6c6fb922efe4b1659c66ea933276965e8"
        tar xf "$CACHEDIR/libiconv-${LIBICONV_VER}.tar.gz" -C "$CACHEDIR"
        # ref https://github.com/msys2/MINGW-packages/blob/7f68e9f2488737bbe03888ade094eaee8021d1c5/mingw-w64-libiconv/PKGBUILD
        info "Building libiconv..."
        cd "$CACHEDIR/libiconv-${LIBICONV_VER}"
        # Patches taken from msys2/MINGW-packages
        patch -p1 < "$here/patches/libiconv-fix-pointer-buf.patch"
        ./configure \
            $AUTOCONF_FLAGS \
            --prefix="/usr/${GCC_TRIPLET_HOST}" \
            --disable-static \
            --enable-shared \
            --enable-extra-encodings \
            --enable-relocatable \
            --disable-rpath \
            --enable-silent-rules \
            --enable-nls
        CC="${GCC_TRIPLET_HOST}-gcc" make "-j$CPU_COUNT" || fail "Could not build libiconv"
        cp -fpv "libcharset/lib/.libs/libcharset-1.dll" "$DLL_TARGET_DIR/" || fail "Could not copy the libcharset binary to DLL_TARGET_DIR"
        cp -fpv "lib/.libs/libiconv-2.dll" "$DLL_TARGET_DIR/" || fail "Could not copy the libiconv binary to DLL_TARGET_DIR"
        # FIXME avoid using sudo
        sudo make install  || fail "Could not install libiconv"
        # workaround to delete files owned by root, created by "make install":
        make clean
    )
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
