#!/bin/bash

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../../.."
CONTRIB="$PROJECT_ROOT/contrib"
CONTRIB_APPIMAGE="$CONTRIB/build-linux/appimage"
DISTDIR="$PROJECT_ROOT/dist"
BUILDDIR="$CONTRIB_APPIMAGE/build/appimage"
APPDIR="$BUILDDIR/electrum.AppDir"
CACHEDIR="$CONTRIB_APPIMAGE/.cache/appimage"

# pinned versions
PYTHON_VERSION=3.6.8
PKG2APPIMAGE_COMMIT="eb8f3acdd9f11ab19b78f5cb15daa772367daf15"
LIBSECP_VERSION="b408c6a8b287003d1ade5709e6f7bc3c7f1d5be7"
SQUASHFSKIT_COMMIT="ae0d656efa2d0df2fcac795b6823b44462f19386"


VERSION=`git describe --tags --dirty --always`
APPIMAGE="$DISTDIR/electrum-$VERSION-x86_64.AppImage"

rm -rf "$BUILDDIR"
mkdir -p "$APPDIR" "$CACHEDIR" "$DISTDIR"


. "$CONTRIB"/build_tools_util.sh


info "downloading some dependencies."
download_if_not_exist "$CACHEDIR/functions.sh" "https://raw.githubusercontent.com/AppImage/pkg2appimage/$PKG2APPIMAGE_COMMIT/functions.sh"
verify_hash "$CACHEDIR/functions.sh" "78b7ee5a04ffb84ee1c93f0cb2900123773bc6709e5d1e43c37519f590f86918"

download_if_not_exist "$CACHEDIR/appimagetool" "https://github.com/AppImage/AppImageKit/releases/download/12/appimagetool-x86_64.AppImage"
verify_hash "$CACHEDIR/appimagetool" "d918b4df547b388ef253f3c9e7f6529ca81a885395c31f619d9aaf7030499a13"

download_if_not_exist "$CACHEDIR/Python-$PYTHON_VERSION.tar.xz" "https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tar.xz"
verify_hash "$CACHEDIR/Python-$PYTHON_VERSION.tar.xz" "35446241e995773b1bed7d196f4b624dadcadc8429f26282e756b2fb8a351193"



info "building python."
tar xf "$CACHEDIR/Python-$PYTHON_VERSION.tar.xz" -C "$BUILDDIR"
(
    cd "$BUILDDIR/Python-$PYTHON_VERSION"
    export SOURCE_DATE_EPOCH=1530212462
    LC_ALL=C export BUILD_DATE=$(date -u -d "@$SOURCE_DATE_EPOCH" "+%b %d %Y")
    LC_ALL=C export BUILD_TIME=$(date -u -d "@$SOURCE_DATE_EPOCH" "+%H:%M:%S")
    # Patch taken from Ubuntu python3.6_3.6.8-1~18.04.1.debian.tar.xz
    patch -p1 < "$CONTRIB_APPIMAGE/patches/python-3.6.8-reproducible-buildinfo.diff"
    ./configure \
      --cache-file="$CACHEDIR/python.config.cache" \
      --prefix="$APPDIR/usr" \
      --enable-ipv6 \
      --enable-shared \
      --with-threads \
      -q
    make -j4 -s || fail "Could not build Python"
    make -s install > /dev/null || fail "Could not install Python"
    # When building in docker on macOS, python builds with .exe extension because the
    # case insensitive file system of macOS leaks into docker. This causes the build
    # to result in a different output on macOS compared to Linux. We simply patch
    # sysconfigdata to remove the extension.
    # Some more info: https://bugs.python.org/issue27631
    sed -i -e 's/\.exe//g' "$APPDIR"/usr/lib/python3.6/_sysconfigdata*
)


info "Building squashfskit"
git clone "https://github.com/squashfskit/squashfskit.git" "$BUILDDIR/squashfskit"
(
    cd "$BUILDDIR/squashfskit"
    git checkout "$SQUASHFSKIT_COMMIT"
    make -C squashfs-tools mksquashfs || fail "Could not build squashfskit"
)
MKSQUASHFS="$BUILDDIR/squashfskit/squashfs-tools/mksquashfs"


info "building libsecp256k1."
(
    git clone https://github.com/bitcoin-core/secp256k1 "$CACHEDIR"/secp256k1 \
        || (cd "$CACHEDIR"/secp256k1 && git reset --hard && git pull)
    cd "$CACHEDIR"/secp256k1
    git reset --hard "$LIBSECP_VERSION"
    git clean -f -x -q
    export SOURCE_DATE_EPOCH=1530212462
    ./autogen.sh
    echo "LDFLAGS = -no-undefined" >> Makefile.am
    ./configure \
      --prefix="$APPDIR/usr" \
      --enable-module-recovery \
      --enable-experimental \
      --enable-module-ecdh \
      --disable-jni \
      -q
    make -j4 -s || fail "Could not build libsecp"
    make -s install > /dev/null || fail "Could not install libsecp"
)


appdir_python() {
  env \
    PYTHONNOUSERSITE=1 \
    LD_LIBRARY_PATH="$APPDIR/usr/lib:$APPDIR/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH+:$LD_LIBRARY_PATH}" \
    "$APPDIR/usr/bin/python3.6" "$@"
}

python='appdir_python'


info "installing pip."
"$python" -m ensurepip


info "preparing electrum-locale."
(
    cd "$PROJECT_ROOT"
    git submodule update --init

    pushd "$CONTRIB"/deterministic-build/electrum-locale
    if ! which msgfmt > /dev/null 2>&1; then
        fail "Please install gettext"
    fi
    for i in ./locale/*; do
        dir="$PROJECT_ROOT/electrum/$i/LC_MESSAGES"
        mkdir -p $dir
        msgfmt --output-file="$dir/electrum.mo" "$i/electrum.po" || true
    done
    popd
)


info "installing electrum and its dependencies."
mkdir -p "$CACHEDIR/pip_cache"
"$python" -m pip install --no-warn-script-location --cache-dir "$CACHEDIR/pip_cache" -r "$CONTRIB/deterministic-build/requirements.txt"
"$python" -m pip install --no-warn-script-location --cache-dir "$CACHEDIR/pip_cache" -r "$CONTRIB/deterministic-build/requirements-binaries.txt"
"$python" -m pip install --no-warn-script-location --cache-dir "$CACHEDIR/pip_cache" -r "$CONTRIB/deterministic-build/requirements-hw.txt"
"$python" -m pip install --no-warn-script-location --cache-dir "$CACHEDIR/pip_cache" "$PROJECT_ROOT"


info "copying zbar"
cp "/usr/lib/libzbar.so.0" "$APPDIR/usr/lib/libzbar.so.0"


info "desktop integration."
cp "$PROJECT_ROOT/electrum.desktop" "$APPDIR/electrum.desktop"
cp "$PROJECT_ROOT/electrum/gui/icons/electrum.png" "$APPDIR/electrum.png"


# add launcher
cp "$CONTRIB_APPIMAGE/apprun.sh" "$APPDIR/AppRun"

info "finalizing AppDir."
(
    export PKG2AICOMMIT="$PKG2APPIMAGE_COMMIT"
    . "$CACHEDIR/functions.sh"

    cd "$APPDIR"
    # copy system dependencies
    copy_deps; copy_deps; copy_deps
    move_lib

    # apply global appimage blacklist to exclude stuff
    # move usr/include out of the way to preserve usr/include/python3.6m.
    mv usr/include usr/include.tmp
    delete_blacklisted
    mv usr/include.tmp usr/include
) || fail "Could not finalize AppDir"

# We copy some libraries here that are on the AppImage excludelist
info "Copying additional libraries"
(
    # On some systems it can cause problems to use the system libusb
    cp -f /usr/lib/x86_64-linux-gnu/libusb-1.0.so "$APPDIR/usr/lib/libusb-1.0.so" || fail "Could not copy libusb"
)

info "stripping binaries from debug symbols."
# "-R .note.gnu.build-id" also strips the build id
strip_binaries()
{
  chmod u+w -R "$APPDIR"
  {
    printf '%s\0' "$APPDIR/usr/bin/python3.6"
    find "$APPDIR" -type f -regex '.*\.so\(\.[0-9.]+\)?$' -print0
  } | xargs -0 --no-run-if-empty --verbose -n1 strip -R .note.gnu.build-id
}
strip_binaries

remove_emptydirs()
{
  find "$APPDIR" -type d -empty -print0 | xargs -0 --no-run-if-empty rmdir -vp --ignore-fail-on-non-empty
}
remove_emptydirs


info "removing some unneeded stuff to decrease binary size."
rm -rf "$APPDIR"/usr/{share,include}
PYDIR="$APPDIR"/usr/lib/python3.6
rm -rf "$PYDIR"/{test,ensurepip,lib2to3,idlelib,turtledemo}
rm -rf "$PYDIR"/{ctypes,sqlite3,tkinter,unittest}/test
rm -rf "$PYDIR"/distutils/{command,tests}
rm -rf "$PYDIR"/config-3.6m-x86_64-linux-gnu
rm -rf "$PYDIR"/site-packages/{opt,pip,setuptools,wheel}
rm -rf "$PYDIR"/site-packages/Cryptodome/SelfTest
rm -rf "$PYDIR"/site-packages/{psutil,qrcode,websocket}/tests
for component in connectivity declarative help location multimedia quickcontrols2 serialport webengine websockets xmlpatterns ; do
  rm -rf "$PYDIR"/site-packages/PyQt5/Qt/translations/qt${component}_*
  rm -rf "$PYDIR"/site-packages/PyQt5/Qt/resources/qt${component}_*
done
rm -rf "$PYDIR"/site-packages/PyQt5/Qt/{qml,libexec}
rm -rf "$PYDIR"/site-packages/PyQt5/{pyrcc.so,pylupdate.so,uic}
rm -rf "$PYDIR"/site-packages/PyQt5/Qt/plugins/{bearer,gamepads,geometryloaders,geoservices,playlistformats,position,renderplugins,sceneparsers,sensors,sqldrivers,texttospeech,webview}
for component in Bluetooth Concurrent Designer Help Location NetworkAuth Nfc Positioning PositioningQuick Qml Quick Sensors SerialPort Sql Test Web Xml ; do
    rm -rf "$PYDIR"/site-packages/PyQt5/Qt/lib/libQt5${component}*
    rm -rf "$PYDIR"/site-packages/PyQt5/Qt${component}*
done
rm -rf "$PYDIR"/site-packages/PyQt5/Qt.so

# these are deleted as they were not deterministic; and are not needed anyway
find "$APPDIR" -path '*/__pycache__*' -delete
rm "$APPDIR"/usr/lib/libsecp256k1.a
rm -rf "$PYDIR"/site-packages/*.dist-info/
rm -rf "$PYDIR"/site-packages/*.egg-info/


find -exec touch -h -d '2000-11-11T11:11:11+00:00' {} +


info "creating the AppImage."
(
    cd "$BUILDDIR"
    cp "$CACHEDIR/appimagetool" "$CACHEDIR/appimagetool_copy"
    # zero out "appimage" magic bytes, as on some systems they confuse the linker
    sed -i 's|AI\x02|\x00\x00\x00|' "$CACHEDIR/appimagetool_copy"
    chmod +x "$CACHEDIR/appimagetool_copy"
    "$CACHEDIR/appimagetool_copy" --appimage-extract
    # We build a small wrapper for mksquashfs that removes the -mkfs-fixed-time option
    # that mksquashfs from squashfskit does not support. It is not needed for squashfskit.
    cat > ./squashfs-root/usr/lib/appimagekit/mksquashfs << EOF
#!/bin/sh
args=\$(echo "\$@" | sed -e 's/-mkfs-fixed-time 0//')
"$MKSQUASHFS" \$args
EOF
    env VERSION="$VERSION" ARCH=x86_64 SOURCE_DATE_EPOCH=1530212462 ./squashfs-root/AppRun --no-appstream --verbose "$APPDIR" "$APPIMAGE"
)


info "done."
ls -la "$DISTDIR"
sha256sum "$DISTDIR"/*
