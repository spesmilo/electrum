#!/bin/bash

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../../.."
CONTRIB="$PROJECT_ROOT/contrib"
DISTDIR="$PROJECT_ROOT/dist"
BUILDDIR="$CONTRIB/build-linux/appimage/build/appimage"
APPDIR="$BUILDDIR/electrum.AppDir"
CACHEDIR="$CONTRIB/build-linux/appimage/.cache/appimage"

# pinned versions
PYTHON_VERSION=3.6.8
PKG2APPIMAGE_COMMIT="83483c2971fcaa1cb0c1253acd6c731ef8404381"
LIBSECP_VERSION="b408c6a8b287003d1ade5709e6f7bc3c7f1d5be7"


VERSION=`git describe --tags --dirty --always`
APPIMAGE="$DISTDIR/electrum-$VERSION-x86_64.AppImage"

rm -rf "$BUILDDIR"
mkdir -p "$APPDIR" "$CACHEDIR" "$DISTDIR"


. "$CONTRIB"/build_tools_util.sh


info "downloading some dependencies."
download_if_not_exist "$CACHEDIR/functions.sh" "https://raw.githubusercontent.com/AppImage/pkg2appimage/$PKG2APPIMAGE_COMMIT/functions.sh"
verify_hash "$CACHEDIR/functions.sh" "a73a21a6c1d1e15c0a9f47f017ae833873d1dc6aa74a4c840c0b901bf1dcf09c"

download_if_not_exist "$CACHEDIR/appimagetool" "https://github.com/probonopd/AppImageKit/releases/download/11/appimagetool-x86_64.AppImage"
verify_hash "$CACHEDIR/appimagetool" "c13026b9ebaa20a17e7e0a4c818a901f0faba759801d8ceab3bb6007dde00372"

download_if_not_exist "$CACHEDIR/Python-$PYTHON_VERSION.tar.xz" "https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tar.xz"
verify_hash "$CACHEDIR/Python-$PYTHON_VERSION.tar.xz" "35446241e995773b1bed7d196f4b624dadcadc8429f26282e756b2fb8a351193"



info "building python."
tar xf "$CACHEDIR/Python-$PYTHON_VERSION.tar.xz" -C "$BUILDDIR"
(
    cd "$BUILDDIR/Python-$PYTHON_VERSION"
    export SOURCE_DATE_EPOCH=1530212462
    TZ=UTC faketime -f '2019-01-01 01:01:01' ./configure \
      --cache-file="$CACHEDIR/python.config.cache" \
      --prefix="$APPDIR/usr" \
      --enable-ipv6 \
      --enable-shared \
      --with-threads \
      -q
    TZ=UTC faketime -f '2019-01-01 01:01:01' make -s
    make -s install > /dev/null
)


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
    make -s
    make -s install > /dev/null
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
        echo "Please install gettext"
        exit 1
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
"$python" -m pip install --cache-dir "$CACHEDIR/pip_cache" -r "$CONTRIB/deterministic-build/requirements.txt"
"$python" -m pip install --cache-dir "$CACHEDIR/pip_cache" -r "$CONTRIB/deterministic-build/requirements-binaries.txt"
"$python" -m pip install --cache-dir "$CACHEDIR/pip_cache" -r "$CONTRIB/deterministic-build/requirements-hw.txt"
"$python" -m pip install --cache-dir "$CACHEDIR/pip_cache" "$PROJECT_ROOT"


info "copying zbar"
cp "/usr/lib/libzbar.so.0" "$APPDIR/usr/lib/libzbar.so.0"


info "desktop integration."
cp "$PROJECT_ROOT/electrum.desktop" "$APPDIR/electrum.desktop"
cp "$PROJECT_ROOT/electrum/gui/icons/electrum.png" "$APPDIR/electrum.png"


# add launcher
cp "$CONTRIB/build-linux/appimage/apprun.sh" "$APPDIR/AppRun"

info "finalizing AppDir."
(
    export PKG2AICOMMIT="$PKG2APPIMAGE_COMMIT"
    . "$CACHEDIR/functions.sh"

    cd "$APPDIR"
    # copy system dependencies
    # note: temporarily move PyQt5 out of the way so
    # we don't try to bundle its system dependencies.
    mv "$APPDIR/usr/lib/python3.6/site-packages/PyQt5" "$BUILDDIR"
    copy_deps; copy_deps; copy_deps
    move_lib
    mv "$BUILDDIR/PyQt5" "$APPDIR/usr/lib/python3.6/site-packages"

    # apply global appimage blacklist to exclude stuff
    # move usr/include out of the way to preserve usr/include/python3.6m.
    mv usr/include usr/include.tmp
    delete_blacklisted
    mv usr/include.tmp usr/include
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
rm -rf "$APPDIR"/usr/lib/python3.6/test
rm -rf "$APPDIR"/usr/lib/python3.6/config-3.6m-x86_64-linux-gnu
rm -rf "$APPDIR"/usr/lib/python3.6/site-packages/PyQt5/Qt/translations/qtwebengine_locales
rm -rf "$APPDIR"/usr/lib/python3.6/site-packages/PyQt5/Qt/resources/qtwebengine_*
rm -rf "$APPDIR"/usr/lib/python3.6/site-packages/PyQt5/Qt/qml
rm -rf "$APPDIR"/usr/lib/python3.6/site-packages/PyQt5/Qt/lib/libQt5Web*
rm -rf "$APPDIR"/usr/lib/python3.6/site-packages/PyQt5/Qt/lib/libQt5Designer*
rm -rf "$APPDIR"/usr/lib/python3.6/site-packages/PyQt5/Qt/lib/libQt5Qml*
rm -rf "$APPDIR"/usr/lib/python3.6/site-packages/PyQt5/Qt/lib/libQt5Quick*
rm -rf "$APPDIR"/usr/lib/python3.6/site-packages/PyQt5/Qt/lib/libQt5Location*
rm -rf "$APPDIR"/usr/lib/python3.6/site-packages/PyQt5/Qt/lib/libQt5Test*
rm -rf "$APPDIR"/usr/lib/python3.6/site-packages/PyQt5/Qt/lib/libQt5Xml*

# these are deleted as they were not deterministic; and are not needed anyway
find "$APPDIR" -path '*/__pycache__*' -delete
rm "$APPDIR"/usr/lib/libsecp256k1.a
rm "$APPDIR"/usr/lib/python3.6/site-packages/pyblake2-*.dist-info/RECORD
rm "$APPDIR"/usr/lib/python3.6/site-packages/hidapi-*.dist-info/RECORD


find -exec touch -h -d '2000-11-11T11:11:11+00:00' {} +


info "creating the AppImage."
(
    cd "$BUILDDIR"
    chmod +x "$CACHEDIR/appimagetool"
    "$CACHEDIR/appimagetool" --appimage-extract
    env VERSION="$VERSION" ARCH=x86_64 ./squashfs-root/AppRun --no-appstream --verbose "$APPDIR" "$APPIMAGE"
)


info "done."
ls -la "$DISTDIR"
sha256sum "$DISTDIR"/*
