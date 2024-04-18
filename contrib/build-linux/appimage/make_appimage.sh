#!/bin/bash

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../../.."
CONTRIB="$PROJECT_ROOT/contrib"
CONTRIB_APPIMAGE="$CONTRIB/build-linux/appimage"
DISTDIR="$PROJECT_ROOT/dist"
BUILDDIR="$CONTRIB_APPIMAGE/build/appimage"
APPDIR="$BUILDDIR/electrum.AppDir"
CACHEDIR="$CONTRIB_APPIMAGE/.cache/appimage"
export DLL_TARGET_DIR="$CACHEDIR/dlls"
PIP_CACHE_DIR="$CONTRIB_APPIMAGE/.cache/pip_cache"

. "$CONTRIB"/build_tools_util.sh

git -C "$PROJECT_ROOT" rev-parse 2>/dev/null || fail "Building outside a git clone is not supported."

export GCC_STRIP_BINARIES="1"

# pinned versions
PYTHON_VERSION=3.11.9
PY_VER_MAJOR="3.11"  # as it appears in fs paths
PKG2APPIMAGE_COMMIT="a9c85b7e61a3a883f4a35c41c5decb5af88b6b5d"

VERSION=$(git describe --tags --dirty --always)
APPIMAGE="$DISTDIR/electrum-$VERSION-x86_64.AppImage"

rm -rf "$BUILDDIR"
mkdir -p "$APPDIR" "$CACHEDIR" "$PIP_CACHE_DIR" "$DISTDIR" "$DLL_TARGET_DIR"

# potential leftover from setuptools that might make pip put garbage in binary
rm -rf "$PROJECT_ROOT/build"


info "downloading some dependencies."
download_if_not_exist "$CACHEDIR/functions.sh" "https://raw.githubusercontent.com/AppImage/pkg2appimage/$PKG2APPIMAGE_COMMIT/functions.sh"
verify_hash "$CACHEDIR/functions.sh" "8f67711a28635b07ce539a9b083b8c12d5488c00003d6d726c7b134e553220ed"

download_if_not_exist "$CACHEDIR/appimagetool" "https://github.com/AppImage/AppImageKit/releases/download/13/appimagetool-x86_64.AppImage"
verify_hash "$CACHEDIR/appimagetool" "df3baf5ca5facbecfc2f3fa6713c29ab9cefa8fd8c1eac5d283b79cab33e4acb"

download_if_not_exist "$CACHEDIR/Python-$PYTHON_VERSION.tar.xz" "https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tar.xz"
verify_hash "$CACHEDIR/Python-$PYTHON_VERSION.tar.xz" "9b1e896523fc510691126c864406d9360a3d1e986acbda59cda57b5abda45b87"



info "building python."
tar xf "$CACHEDIR/Python-$PYTHON_VERSION.tar.xz" -C "$CACHEDIR"
(
    if [ -f "$CACHEDIR/Python-$PYTHON_VERSION/python" ]; then
        info "python already built, skipping"
        exit 0
    fi
    cd "$CACHEDIR/Python-$PYTHON_VERSION"
    LC_ALL=C export BUILD_DATE=$(date -u -d "@$SOURCE_DATE_EPOCH" "+%b %d %Y")
    LC_ALL=C export BUILD_TIME=$(date -u -d "@$SOURCE_DATE_EPOCH" "+%H:%M:%S")
    # Patches taken from Ubuntu http://archive.ubuntu.com/ubuntu/pool/main/p/python3.11/python3.11_3.11.6-3.debian.tar.xz
    patch -p1 < "$CONTRIB_APPIMAGE/patches/python-3.11-reproducible-buildinfo.diff"
    ./configure \
        --cache-file="$CACHEDIR/python.config.cache" \
        --prefix="$APPDIR/usr" \
        --enable-ipv6 \
        --enable-shared \
        -q
    make "-j$CPU_COUNT" -s || fail "Could not build Python"
)
info "installing python."
(
    cd "$CACHEDIR/Python-$PYTHON_VERSION"
    make -s install > /dev/null || fail "Could not install Python"
    # When building in docker on macOS, python builds with .exe extension because the
    # case insensitive file system of macOS leaks into docker. This causes the build
    # to result in a different output on macOS compared to Linux. We simply patch
    # sysconfigdata to remove the extension.
    # Some more info: https://bugs.python.org/issue27631
    sed -i -e 's/\.exe//g' "${APPDIR}/usr/lib/python${PY_VER_MAJOR}"/_sysconfigdata*
)


if [ -f "$DLL_TARGET_DIR/libsecp256k1.so.2" ]; then
    info "libsecp256k1 already built, skipping"
else
    "$CONTRIB"/make_libsecp256k1.sh || fail "Could not build libsecp"
fi
cp -f "$DLL_TARGET_DIR"/libsecp256k1.so.* "$APPDIR/usr/lib/" || fail "Could not copy libsecp to its destination"


if [ -f "$DLL_TARGET_DIR/libzbar.so.0" ]; then
    info "libzbar already built, skipping"
else
    # note: could instead just use the libzbar0 pkg from debian/apt, but that is too old and missing fixes for CVE-2023-40889
    "$CONTRIB"/make_zbar.sh || fail "Could not build zbar"
fi
cp -f "$DLL_TARGET_DIR/libzbar.so.0" "$APPDIR/usr/lib/" || fail "Could not copy libzbar to its destination"


# note: libxcb-util1 is not available in debian 10 (buster), only libxcb-util0. So we build it ourselves.
#       This pkg is needed on some distros for Qt to launch. (see #8011)
info "building libxcb-util1."
XCB_UTIL_VERSION="acf790d7752f36e450d476ad79807d4012ec863b"
# ^ git tag 0.4.0
(
    if [ -f "$CACHEDIR/libxcb-util1/util/src/.libs/libxcb-util.so.1" ]; then
        info "libxcb-util1 already built, skipping"
        exit 0
    fi
    cd "$CACHEDIR"
    mkdir "libxcb-util1"
    cd "libxcb-util1"
    if [ ! -d util ]; then
        git clone --recursive "https://anongit.freedesktop.org/git/xcb/util"
    fi
    cd util
    if ! $(git cat-file -e ${XCB_UTIL_VERSION}) ; then
        info "Could not find requested version $XCB_UTIL_VERSION in local clone; fetching..."
        git fetch --all
        git submodule update
    fi
    git reset --hard
    git clean -dfxq
    git checkout "${XCB_UTIL_VERSION}^{commit}"
    ./autogen.sh
    ./configure --enable-shared
    make "-j$CPU_COUNT" -s || fail "Could not build libxcb-util1"
) || fail "Could build libxcb-util1"
cp "$CACHEDIR/libxcb-util1/util/src/.libs/libxcb-util.so.1" "$APPDIR/usr/lib/libxcb-util.so.1"


appdir_python() {
    env \
        PYTHONNOUSERSITE=1 \
        LD_LIBRARY_PATH="$APPDIR/usr/lib:$APPDIR/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH+:$LD_LIBRARY_PATH}" \
        "$APPDIR/usr/bin/python${PY_VER_MAJOR}" "$@"
}

python='appdir_python'


info "installing pip."
"$python" -m ensurepip

break_legacy_easy_install


info "preparing electrum-locale."
(
    cd "$PROJECT_ROOT"
    git submodule update --init

    LOCALE="$PROJECT_ROOT/electrum/locale/"
    # we want the binary to have only compiled (.mo) locale files; not source (.po) files
    rm -rf "$LOCALE"
    "$CONTRIB/build_locale.sh" "$CONTRIB/deterministic-build/electrum-locale/locale/" "$LOCALE"
)


info "Installing build dependencies."
# note: re pip installing from PyPI,
#       we prefer compiling C extensions ourselves, instead of using binary wheels,
#       hence "--no-binary :all:" flags. However, we specifically allow
#       - PyQt5, as it's harder to build from source
#       - cryptography, as it's harder to build from source
#       - the whole of "requirements-build-base.txt", which includes pip and friends, as it also includes "wheel",
#         and I am not quite sure how to break the circular dependence there (I guess we could introduce
#         "requirements-build-base-base.txt" with just wheel in it...)
"$python" -m pip install --no-build-isolation --no-dependencies --no-warn-script-location \
    --cache-dir "$PIP_CACHE_DIR" -r "$CONTRIB/deterministic-build/requirements-build-base.txt"
"$python" -m pip install --no-build-isolation --no-dependencies --no-binary :all: --no-warn-script-location \
    --cache-dir "$PIP_CACHE_DIR" -r "$CONTRIB/deterministic-build/requirements-build-appimage.txt"

info "installing electrum and its dependencies."
"$python" -m pip install --no-build-isolation --no-dependencies --no-binary :all: --no-warn-script-location \
    --cache-dir "$PIP_CACHE_DIR" -r "$CONTRIB/deterministic-build/requirements.txt"
"$python" -m pip install --no-build-isolation --no-dependencies --no-binary :all: --only-binary PyQt5,PyQt5-Qt5,cryptography --no-warn-script-location \
    --cache-dir "$PIP_CACHE_DIR" -r "$CONTRIB/deterministic-build/requirements-binaries.txt"
"$python" -m pip install --no-build-isolation --no-dependencies --no-binary :all: --no-warn-script-location \
    --cache-dir "$PIP_CACHE_DIR" -r "$CONTRIB/deterministic-build/requirements-hw.txt"

"$python" -m pip install --no-build-isolation --no-dependencies --no-warn-script-location \
    --cache-dir "$PIP_CACHE_DIR" "$PROJECT_ROOT"

# was only needed during build time, not runtime
"$python" -m pip uninstall -y Cython


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
    # move usr/include out of the way to preserve usr/include/python${PY_VER_MAJOR}.
    mv usr/include usr/include.tmp
    delete_blacklisted
    mv usr/include.tmp usr/include
) || fail "Could not finalize AppDir"

info "Copying additional libraries"
(
    # On some systems it can cause problems to use the system libusb (on AppImage excludelist)
    cp -f /usr/lib/x86_64-linux-gnu/libusb-1.0.so "$APPDIR/usr/lib/libusb-1.0.so" || fail "Could not copy libusb"
    # some distros lack libxkbcommon-x11
    cp -f /usr/lib/x86_64-linux-gnu/libxkbcommon-x11.so.0 "$APPDIR"/usr/lib/x86_64-linux-gnu || fail "Could not copy libxkbcommon-x11"
    # some distros lack some libxcb libraries (see https://github.com/Electron-Cash/Electron-Cash/issues/2196)
    cp -f /usr/lib/x86_64-linux-gnu/libxcb-* "$APPDIR"/usr/lib/x86_64-linux-gnu || fail "Could not copy libxcb"
)

info "stripping binaries from debug symbols."
# "-R .note.gnu.build-id" also strips the build id
# "-R .comment" also strips the GCC version information
strip_binaries()
{
    chmod u+w -R "$APPDIR"
    {
        printf '%s\0' "$APPDIR/usr/bin/python${PY_VER_MAJOR}"
        find "$APPDIR" -type f -regex '.*\.so\(\.[0-9.]+\)?$' -print0
    } | xargs -0 --no-run-if-empty --verbose strip -R .note.gnu.build-id -R .comment
}
strip_binaries

remove_emptydirs()
{
    find "$APPDIR" -type d -empty -print0 | xargs -0 --no-run-if-empty rmdir -vp --ignore-fail-on-non-empty
}
remove_emptydirs


info "removing some unneeded stuff to decrease binary size."
rm -rf "$APPDIR"/usr/{share,include}
PYDIR="$APPDIR/usr/lib/python${PY_VER_MAJOR}"
rm -rf "$PYDIR"/{test,ensurepip,lib2to3,idlelib,turtledemo}
rm -rf "$PYDIR"/{ctypes,sqlite3,tkinter,unittest}/test
rm -rf "$PYDIR"/distutils/{command,tests}
rm -rf "$PYDIR"/config-3.*-x86_64-linux-gnu
rm -rf "$PYDIR"/site-packages/{opt,pip,setuptools,wheel}
rm -rf "$PYDIR"/site-packages/Cryptodome/SelfTest
rm -rf "$PYDIR"/site-packages/{psutil,qrcode,websocket}/tests
# rm lots of unused parts of Qt/PyQt. (assuming PyQt 5.15.3+ layout)
for component in connectivity declarative help location multimedia quickcontrols2 serialport webengine websockets xmlpatterns ; do
    rm -rf "$PYDIR"/site-packages/PyQt5/Qt5/translations/qt${component}_*
    rm -rf "$PYDIR"/site-packages/PyQt5/Qt5/resources/qt${component}_*
done
rm -rf "$PYDIR"/site-packages/PyQt5/Qt5/{qml,libexec}
rm -rf "$PYDIR"/site-packages/PyQt5/{pyrcc*.so,pylupdate*.so,uic}
rm -rf "$PYDIR"/site-packages/PyQt5/Qt5/plugins/{bearer,gamepads,geometryloaders,geoservices,playlistformats,position,renderplugins,sceneparsers,sensors,sqldrivers,texttospeech,webview}
for component in Bluetooth Concurrent Designer Help Location NetworkAuth Nfc Positioning PositioningQuick Qml Quick Sensors SerialPort Sql Test Web Xml ; do
    rm -rf "$PYDIR"/site-packages/PyQt5/Qt5/lib/libQt5${component}*
    rm -rf "$PYDIR"/site-packages/PyQt5/Qt${component}*
done
rm -rf "$PYDIR"/site-packages/PyQt5/Qt.so

# these are deleted as they were not deterministic; and are not needed anyway
find "$APPDIR" -path '*/__pycache__*' -delete
# although note that *.dist-info might be needed by certain packages...
# e.g. importlib-metadata, see https://gitlab.com/python-devs/importlib_metadata/issues/71
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
    # We build a small wrapper for mksquashfs that removes the -mkfs-time option
    # as it conflicts with SOURCE_DATE_EPOCH.
    mv "$BUILDDIR/squashfs-root/usr/lib/appimagekit/mksquashfs" "$BUILDDIR/squashfs-root/usr/lib/appimagekit/mksquashfs_orig"
    cat > "$BUILDDIR/squashfs-root/usr/lib/appimagekit/mksquashfs" << EOF
#!/bin/sh
args=\$(echo "\$@" | sed -e 's/-mkfs-time 0//')
"$BUILDDIR/squashfs-root/usr/lib/appimagekit/mksquashfs_orig" \$args
EOF
    chmod +x "$BUILDDIR/squashfs-root/usr/lib/appimagekit/mksquashfs"
    env VERSION="$VERSION" ARCH=x86_64 ./squashfs-root/AppRun --no-appstream --verbose "$APPDIR" "$APPIMAGE"
)


info "done."
ls -la "$DISTDIR"
sha256sum "$DISTDIR"/*
