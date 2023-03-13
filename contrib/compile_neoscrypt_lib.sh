#!/bin/bash
set -e
(
. $(dirname "$0")/build_tools_util.sh || (info "Could not source build_tools_util.sh" && exit 1)

here=$(dirname $(realpath "$0" 2> /dev/null || grealpath "$0"))
CONTRIB="$here"
PROJECT_ROOT="$CONTRIB/.."

if [ -z "$BUILD_TYPE" ] ; then
    export WIN_ARCH="linux"  # default
fi
pkgname="neoscrypt_module"
dlname="neoscrypt"

info "Building $pkgname..."


cd "$CONTRIB/$pkgname"
rm -f "*.o"
CFLAGS="-Wall -O2 -fPIC -fomit-frame-pointer -fno-stack-protector  -I/usr/include/python3.8/"
LDFLAGS="-shared -W -static-libgcc -static-libstdc++" #l," #,-s"

case  $BUILD_TYPE in
    wine)
        CC="x86_64-w64-mingw32-gcc"
        libname="lib$dlname-0.dll"
        ;;
    linux)
        CC="gcc"
        libname="lib$dlname.so.0"

        ;;
esac
LD=$CC





info "$CC $CFLAGS $DEFINES -c $dlname.c"
`$CC $CFLAGS $DEFINES -c $dlname.c`|| fail "failed to compile $dlname"

info "$LD $LDFLAGS -o $libname $dlname.o"
`$LD $LDFLAGS -o "$libname" "$dlname.o"`
 host_strip $libname
cp -fpv "$libname" "$PROJECT_ROOT/electrum" || fail "Could not copy the $pkgname binary to its destination"
    info "'$libname' has been placed in the inner 'electrum' folder."
    if [ -n "$DLL_TARGET_DIR" ] ; then
        cp -fpv "$libname" "$DLL_TARGET_DIR" || fail "Could not copy the $pkgname binary to DLL_TARGET_DIR"
        info "'$libname' has been placed in $DLL_TARGET_DIR."
    fi
cd -
)
