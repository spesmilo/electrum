#!/usr/bin/env bash
#
# Builds the unsigned macOS apps and DMGs, one per architecture:
#   dist/x86_64/Electrum.app  and  dist/electrum-$VERSION-x86_64-unsigned.dmg
#   dist/arm64/Electrum.app   and  dist/electrum-$VERSION-arm64-unsigned.dmg
# Both apps come from one build environment with universal2 (x86_64 + arm64) binaries;
# PyInstaller thins each app to its architecture.

set -e

export LC_ALL=C TZ=UTC
export MACOSX_DEPLOYMENT_TARGET=12.0
export PYTHONDONTWRITEBYTECODE=1  # don't create __pycache__/ folders with .pyc files
export GCC_STRIP_BINARIES=1

# Parameterize
PACKAGE=Electrum
ARCHS="x86_64 arm64"

# Python: python.org's universal2 installer
PYTHON_VERSION=3.14.10
PY_VER_MAJOR="3.14"  # as it appears in fs paths
PYTHON_PKG="python-$PYTHON_VERSION-macos11.pkg"
PYTHON_PKG_SHA256=286c7018aa2730f6747ca433dccdc2b31be45f078a9ea0ffa44d5f06368fd2d7

# GNU autotools, in build order: path below https://ftp.gnu.org/gnu/, and sha256
AUTOTOOLS="m4/m4-1.4.19.tar.xz 63aede5c6d33b6d9b13511cd0be2cac046f2e70fd0a07aa9573a04a82783af96
autoconf/autoconf-2.72.tar.xz ba885c1319578d6c94d46e9b0dceb4014caafe2490e437a0dbca3f270a223f5a
automake/automake-1.17.tar.xz 8920c1fc411e13b90bf704ef9db6f29d540e76d232cb3b2c9f4dc4cc599bd990
libtool/libtool-2.5.4.tar.xz f81f5860666b0bc7d84baddefa60d1cb9fa6fceb2398cc3baca6afaa60266675"

# cmake: Kitware's universal build
CMAKE_VERSION=3.31.6
CMAKE_DIST="cmake-$CMAKE_VERSION-macos10.10-universal"
CMAKE_SHA256=dc49fe67e0841e1d21b9e694d4858bbc06118165be5ebd8da0f2028216d56e6c

PYINSTALLER_REPO="https://github.com/pyinstaller/pyinstaller.git"
PYINSTALLER_COMMIT="7c5dcd97a7679c5f3b04c43a0aae0ffeabe7462b"
# ^ tag "v6.15.0"

. "$(dirname "$0")/../build_tools_util.sh"

CONTRIB_OSX="$(dirname "$(realpath "$0")")"
CONTRIB="$CONTRIB_OSX/.."
PROJECT_ROOT="$CONTRIB/.."
CACHEDIR="$CONTRIB_OSX/.cache"
VENV_DIR="$CONTRIB_OSX/build-venv"

cd "$PROJECT_ROOT"

git -C "$PROJECT_ROOT" rev-parse || fail "Building outside a git clone is not supported."

rm -rf "$CACHEDIR" "$VENV_DIR" build dist Electrum.egg-info electrum/*.dylib
mkdir -p "$CACHEDIR"


info "Installing Python $PYTHON_VERSION"
download_if_not_exist "$CACHEDIR/$PYTHON_PKG" "https://www.python.org/ftp/python/$PYTHON_VERSION/$PYTHON_PKG"
verify_hash "$CACHEDIR/$PYTHON_PKG" "$PYTHON_PKG_SHA256"
sudo installer -pkg "$CACHEDIR/$PYTHON_PKG" -target / \
    || fail "failed to install python"

# sanity check "python3" has the version we just installed.
FOUND_PY_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')
if [[ "$FOUND_PY_VERSION" != "$PYTHON_VERSION" ]]; then
    fail "python version mismatch: $FOUND_PY_VERSION != $PYTHON_VERSION"
fi

break_legacy_easy_install

info "Installing build tools"
mkdir -p "$CACHEDIR/bin"
export PATH="$CACHEDIR/bin:$CACHEDIR/autotools/bin:$PATH"  # note: GNU libtool shadows Apple's libtool

# GNU autotools, for libsecp256k1 and libusb.
while read -r path sha256; do
    tarball="$CACHEDIR/$(basename "$path")"
    download_if_not_exist "$tarball" "https://ftp.gnu.org/gnu/$path"
    verify_hash "$tarball" "$sha256"
    tar -xJf "$tarball" -C "$CACHEDIR"
    (
        cd "$CACHEDIR/$(basename "$path" .tar.xz)"
        ./configure --prefix="$CACHEDIR/autotools" > configure.log
        make "-j$CPU_COUNT" > make.log
        make install > install.log
    ) || fail "Could not build $(basename "$path" .tar.xz), see $CACHEDIR"
done <<< "$AUTOTOOLS"

# cmake, for zxing-cpp: Kitware's universal build
download_if_not_exist "$CACHEDIR/$CMAKE_DIST.tar.gz" \
    "https://github.com/Kitware/CMake/releases/download/v$CMAKE_VERSION/$CMAKE_DIST.tar.gz"
verify_hash "$CACHEDIR/$CMAKE_DIST.tar.gz" "$CMAKE_SHA256"
mkdir "$CACHEDIR/cmake"
tar -xzf "$CACHEDIR/$CMAKE_DIST.tar.gz" -C "$CACHEDIR/cmake" --strip-components 3 \
    "$CMAKE_DIST/CMake.app/Contents/bin/cmake" "$CMAKE_DIST/CMake.app/Contents/share" \
    || fail "Could not unpack $CMAKE_DIST"
export PATH="$CACHEDIR/cmake/bin:$PATH"

# msgfmt (gettext) for the locale: CPython's msgfmt.py, which the python.org pkg ships
ln -s "/Library/Frameworks/Python.framework/Versions/$PY_VER_MAJOR/share/doc/python$PY_VER_MAJOR/examples/Tools/i18n/msgfmt.py" \
    "$CACHEDIR/bin/msgfmt"


python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# Settings for C extensions that pip compiles from source:
# - ARCHFLAGS: build universal2 (x86_64 + arm64) binaries, which both apps need.
# - CFLAGS: python.org's own flags (-O3 -DNDEBUG ...), then -g0 to undo their -g. They must be given
#   in full: setuptools uses an exported CFLAGS instead of them, not in addition [0]. The -arch flags
#   among them have no effect: setuptools passes each compiler command through CPython's
#   compiler_fixup(), which drops all -arch flags and appends ARCHFLAGS [1].
# [0]: https://github.com/pypa/setuptools/blob/049815b259805879f2fd60987f1d9e0d39c9dc96/setuptools/_distutils/sysconfig.py#L347-L349
# [1]: https://github.com/python/cpython/blob/b703b2c5e704341d61e367b9b940b77ed11dded0/Lib/_osx_support.py#L379-L397
export ARCHFLAGS="-arch x86_64 -arch arm64"
EXT_CFLAGS="$(python3 -c 'import sysconfig; print(sysconfig.get_config_var("CFLAGS"), "-g0")')"
info "C extensions: ARCHFLAGS=$ARCHFLAGS, CFLAGS=$EXT_CFLAGS"
pip_install() {  # args...: C extensions get EXT_CFLAGS, which no other build should get
    CFLAGS="$EXT_CFLAGS" CXXFLAGS="$EXT_CFLAGS" python3 -m pip install --no-build-isolation --no-dependencies \
        --no-warn-script-location --no-cache-dir "$@"
}

info "Installing build dependencies"
# note: re pip installing from PyPI,
#       we prefer compiling C extensions ourselves, instead of using binary wheels,
#       hence "--no-binary :all:" flags. However, we specifically allow
#       - PyQt6, as it's harder to build from source
#       - cryptography, as it's harder to build from source
#       - the whole of "requirements-build-base.txt", which includes pip and friends, as it also includes "wheel",
#         and I am not quite sure how to break the circular dependence there (I guess we could introduce
#         "requirements-build-base-base.txt" with just wheel in it...)
pip_install -Ir ./contrib/deterministic-build/requirements-build-base.txt \
    || fail "Could not install build dependencies (base)"
pip_install --no-binary :all: -Ir ./contrib/deterministic-build/requirements-build-mac.txt \
    || fail "Could not install build dependencies (mac)"


info "Building native libraries"
# All three as universal2 binaries in one pass, with Apple clang. The scripts copy them to electrum/.
(
    export CC=clang CXX=clang++
    CMAKE_OSX_ARCHITECTURES="x86_64;arm64" "$CONTRIB"/make_zxing.sh || fail "Could not build zxing-cpp dylib"
    # (CFLAGS replaces autoconf's default "-g -O2"; the -arch flags reach the linker through CFLAGS)
    CFLAGS="-O2 $ARCHFLAGS" "$CONTRIB"/make_libsecp256k1.sh || fail "Could not build libsecp"
    CFLAGS="-O2 $ARCHFLAGS" "$CONTRIB"/make_libusb.sh || fail "Could not build libusb dylib"
) || fail "Could not build the native libraries"


info "Building PyInstaller."
(
    ELECTRUM_COMMIT_HASH=$(git rev-parse HEAD)
    mkdir "$CACHEDIR/pyinstaller"
    cd "$CACHEDIR/pyinstaller"
    # Shallow clone
    git init -q
    git remote add origin $PYINSTALLER_REPO
    git fetch -q --depth 1 origin $PYINSTALLER_COMMIT
    git checkout -q -b pinned "${PYINSTALLER_COMMIT}^{commit}"
    rm -fv PyInstaller/bootloader/Darwin-*/run* || true
    # add reproducible randomness. this ensures we build a different bootloader for each commit.
    # if we built the same one for all releases, that might also get anti-virus false positives
    echo "const char *electrum_tag = \"tagged by Electrum@$ELECTRUM_COMMIT_HASH\";" >> ./bootloader/src/pyi_main.c
    pushd bootloader
    # compile bootloader (universal2 by default)
    python3 ./waf all CFLAGS="-static"
    popd
    # sanity check bootloader is there:
    [ "$(lipo -archs PyInstaller/bootloader/Darwin-64bit/runw)" = "x86_64 arm64" ] \
        || fail "Could not find a universal2 runw in target dir!"
) || fail "Could not build the PyInstaller bootloader"
info "Installing PyInstaller."
pip_install "$CACHEDIR/pyinstaller" || fail "Could not install PyInstaller"

info "Using these versions for building $PACKAGE:"
sw_vers
python3 --version
echo -n "Pyinstaller "
pyinstaller --version

info "resetting git submodules."
# note: --force is less critical in other build scripts, but as the mac build is not doing a fresh clone,
#       it is very useful here for reproducibility
git submodule update --init --force

info "preparing electrum-locale."
"$CONTRIB/locale/build_cleanlocale.sh" || fail "Could not prepare the locale"
# we want the binary to have only compiled (.mo) locale files; not source (.po) files
rm -r "$PROJECT_ROOT/electrum/locale/locale"/*/electrum.po


# opt out of compiling C extensions
export YARL_NO_EXTENSIONS=1
export PROPCACHE_NO_EXTENSIONS=1
export MULTIDICT_NO_EXTENSIONS=1

export ELECTRUM_ECC_DONT_COMPILE=1

info "Installing requirements..."
pip_install --no-binary :all: \
    -Ir ./contrib/deterministic-build/requirements.txt \
    || fail "Could not install requirements"

info "Installing hardware wallet requirements..."
pip_install --no-binary :all: --only-binary cryptography \
    -Ir ./contrib/deterministic-build/requirements-hw.txt \
    || fail "Could not install hardware wallet requirements"

info "Installing dependencies specific to binaries..."
pip_install --no-binary :all: --only-binary PyQt6,PyQt6-Qt6,cryptography \
    -Ir ./contrib/deterministic-build/requirements-binaries-mac.txt \
    || fail "Could not install dependencies specific to binaries"
# PyQt6-Qt6 has separate x86_64 and arm64 wheels, and pip installed the one for this machine above.
# Both are unpacked into their own directories, and lipo fuses each file that differs into the venv.
# The venv then has a "universal" Qt, from which PyInstaller takes the slice for each app's architecture.
for arch in $ARCHS; do
    # (macosx_12_0: the wheel that runs on macOS 12)
    pip_install --require-hashes --only-binary :all: --platform "macosx_12_0_$arch" --target "$CACHEDIR/qt6-$arch" \
        -c ./contrib/deterministic-build/requirements-binaries-mac.txt PyQt6-Qt6 \
        || fail "Could not install the PyQt6-Qt6 wheel for $arch"
done
while read -r f; do
    x86_64="$CACHEDIR/qt6-x86_64/$f" arm64="$CACHEDIR/qt6-arm64/$f"
    cmp -s "$arm64" "$x86_64" && continue
    lipo -create "$arm64" "$x86_64" -output "$VENV_DIR/lib/python$PY_VER_MAJOR/site-packages/$f" \
        || fail "Could not fuse $f"
done < <(cd "$CACHEDIR/qt6-arm64" && find PyQt6 -type f)

info "Building $PACKAGE..."
pip_install . > /dev/null || fail "Could not build $PACKAGE"
# pyinstaller needs to be able to "import electrum_ecc", for which we need libsecp256k1:
# (or could try "pip install -e" instead)
cp electrum/libsecp256k1.*.dylib "$VENV_DIR/lib/python$PY_VER_MAJOR/site-packages/electrum_ecc/"

# strip debug symbols of some compiled libs
# - hidapi (hid.cpython-39-darwin.so) in particular is not reproducible without this
find "$VENV_DIR/lib/python$PY_VER_MAJOR/site-packages/" -type f -name '*.so' -print0 \
    | xargs -0 -t strip -x

# note: no --dirty, as we have dirtied electrum/locale/ ourselves.
VERSION=$(git describe --tags --always --abbrev=10)

for arch in $ARCHS; do
    info "Building binary for $arch"
    ELECTRUM_VERSION=$VERSION ELECTRUM_TARGET_ARCH=$arch pyinstaller --noconfirm --clean \
        --distpath "dist/$arch" --workpath "build/$arch" contrib/osx/pyinstaller.spec \
        || fail "Could not build binary for $arch"
done

for arch in $ARCHS; do
    info "Creating unsigned .DMG for $arch"
    hdiutil create -fs HFS+ -volname $PACKAGE -srcfolder "dist/$arch/$PACKAGE.app" \
        "dist/electrum-$VERSION-$arch-unsigned.dmg" || fail "Could not create .DMG"
done

info "Finished building unsigned apps. These hashes should be reproducible:"
for arch in $ARCHS; do
    # one hash over all files, directories and symlinks of the app
    "$CONTRIB_OSX/codesign_replay.py" manifest "dist/$arch/$PACKAGE.app" > "$CACHEDIR/$arch.manifest" \
        || fail "Could not hash dist/$arch/$PACKAGE.app"
    echo "$(shasum -a 256 < "$CACHEDIR/$arch.manifest" | cut -d ' ' -f 1)  dist/$arch/$PACKAGE.app"
done

info "Apps were built successfully but were not code signed. Users may get security warnings from macOS."
info "Now you also need to run sign_osx.sh to codesign/notarize the binaries."
