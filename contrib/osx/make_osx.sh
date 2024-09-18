#!/usr/bin/env bash

set -e

# Parameterize
PYTHON_VERSION=3.11.9
PY_VER_MAJOR="3.11"  # as it appears in fs paths
PACKAGE=Electrum
GIT_REPO=https://github.com/spesmilo/electrum

export GCC_STRIP_BINARIES="1"
export PYTHONDONTWRITEBYTECODE=1  # don't create __pycache__/ folders with .pyc files


. "$(dirname "$0")/../build_tools_util.sh"


CONTRIB_OSX="$(dirname "$(realpath "$0")")"
CONTRIB="$CONTRIB_OSX/.."
PROJECT_ROOT="$CONTRIB/.."
CACHEDIR="$CONTRIB_OSX/.cache"
export DLL_TARGET_DIR="$CACHEDIR/dlls"

mkdir -p "$CACHEDIR" "$DLL_TARGET_DIR"

cd "$PROJECT_ROOT"

git -C "$PROJECT_ROOT" rev-parse 2>/dev/null || fail "Building outside a git clone is not supported."


which brew > /dev/null 2>&1 || fail "Please install brew from https://brew.sh/ to continue"
which xcodebuild > /dev/null 2>&1 || fail "Please install xcode command line tools to continue"


info "Installing Python $PYTHON_VERSION"
PKG_FILE="python-${PYTHON_VERSION}-macos11.pkg"
if [ ! -f "$CACHEDIR/$PKG_FILE" ]; then
    curl -o "$CACHEDIR/$PKG_FILE" "https://www.python.org/ftp/python/${PYTHON_VERSION}/$PKG_FILE"
fi
echo "b6cfdee2571ca56ee895043ca1e7110fb78a878cee3eb0c21accb2de34d24b55  $CACHEDIR/$PKG_FILE" | shasum -a 256 -c \
    || fail "python pkg checksum mismatched"
sudo installer -pkg "$CACHEDIR/$PKG_FILE" -target / \
    || fail "failed to install python"

# sanity check "python3" has the version we just installed.
FOUND_PY_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')
if [[ "$FOUND_PY_VERSION" != "$PYTHON_VERSION" ]]; then
    fail "python version mismatch: $FOUND_PY_VERSION != $PYTHON_VERSION"
fi

break_legacy_easy_install

# create a fresh virtualenv
# This helps to avoid older versions of pip-installed dependencies interfering with the build.
VENV_DIR="$CONTRIB_OSX/build-venv"
rm -rf "$VENV_DIR"
python3 -m venv $VENV_DIR
source $VENV_DIR/bin/activate

# don't add debug info to compiled C files (e.g. when pip calls setuptools/wheel calls gcc)
# see https://github.com/pypa/pip/issues/6505#issuecomment-526613584
# note: this does not seem sufficient when cython is involved (although it is on linux, just not on mac... weird.)
#       see additional "strip" pass on built files later in the file.
export CFLAGS="-g0"

# Do not build universal binaries. The default on macos 11+ and xcode 12+ is "-arch arm64 -arch x86_64"
# but with that e.g. "hid.cpython-310-darwin.so" is not reproducible as built by clang.
export ARCHFLAGS="-arch x86_64"

info "Installing build dependencies"
# note: re pip installing from PyPI,
#       we prefer compiling C extensions ourselves, instead of using binary wheels,
#       hence "--no-binary :all:" flags. However, we specifically allow
#       - PyQt6, as it's harder to build from source
#       - cryptography, as it's harder to build from source
#       - the whole of "requirements-build-base.txt", which includes pip and friends, as it also includes "wheel",
#         and I am not quite sure how to break the circular dependence there (I guess we could introduce
#         "requirements-build-base-base.txt" with just wheel in it...)
python3 -m pip install --no-build-isolation --no-dependencies --no-warn-script-location \
    -Ir ./contrib/deterministic-build/requirements-build-base.txt \
    || fail "Could not install build dependencies (base)"
python3 -m pip install --no-build-isolation --no-dependencies --no-binary :all: --no-warn-script-location \
    -Ir ./contrib/deterministic-build/requirements-build-mac.txt \
    || fail "Could not install build dependencies (mac)"

info "Installing some build-time deps for compilation..."
brew install autoconf automake libtool gettext coreutils pkgconfig

info "Building PyInstaller."
PYINSTALLER_REPO="https://github.com/pyinstaller/pyinstaller.git"
PYINSTALLER_COMMIT="5d7a0449ecea400eccbbb30d5fcef27d72f8f75d"
# ^ tag "v6.6.0"
(
    if [ -f "$CACHEDIR/pyinstaller/PyInstaller/bootloader/Darwin-64bit/runw" ]; then
        info "pyinstaller already built, skipping"
        exit 0
    fi
    cd "$PROJECT_ROOT"
    ELECTRUM_COMMIT_HASH=$(git rev-parse HEAD)
    cd "$CACHEDIR"
    rm -rf pyinstaller
    mkdir pyinstaller
    cd pyinstaller
    # Shallow clone
    git init
    git remote add origin $PYINSTALLER_REPO
    git fetch --depth 1 origin $PYINSTALLER_COMMIT
    git checkout -b pinned "${PYINSTALLER_COMMIT}^{commit}"
    rm -fv PyInstaller/bootloader/Darwin-*/run* || true
    # add reproducible randomness. this ensures we build a different bootloader for each commit.
    # if we built the same one for all releases, that might also get anti-virus false positives
    echo "const char *electrum_tag = \"tagged by Electrum@$ELECTRUM_COMMIT_HASH\";" >> ./bootloader/src/pyi_main.c
    pushd bootloader
    # compile bootloader
    python3 ./waf all CFLAGS="-static"
    popd
    # sanity check bootloader is there:
    [[ -e "PyInstaller/bootloader/Darwin-64bit/runw" ]] || fail "Could not find runw in target dir!"
) || fail "PyInstaller build failed"
info "Installing PyInstaller."
python3 -m pip install --no-build-isolation --no-dependencies --no-warn-script-location "$CACHEDIR/pyinstaller"

info "Using these versions for building $PACKAGE:"
sw_vers
python3 --version
echo -n "Pyinstaller "
pyinstaller --version

rm -rf ./dist

git submodule update --init

info "generating locale"
(
    if ! which msgfmt > /dev/null 2>&1; then
        brew install gettext
        brew link --force gettext
    fi
    LOCALE="$PROJECT_ROOT/electrum/locale/"
    # we want the binary to have only compiled (.mo) locale files; not source (.po) files
    rm -rf "$LOCALE"
    "$CONTRIB/build_locale.sh" "$CONTRIB/deterministic-build/electrum-locale/locale/" "$LOCALE"
) || fail "failed generating locale"


if [ ! -f "$DLL_TARGET_DIR/libsecp256k1.2.dylib" ]; then
    info "Building libsecp256k1 dylib..."
    "$CONTRIB"/make_libsecp256k1.sh || fail "Could not build libsecp"
else
    info "Skipping libsecp256k1 build: reusing already built dylib."
fi
cp -f "$DLL_TARGET_DIR"/libsecp256k1.*.dylib "$PROJECT_ROOT/electrum/" || fail "Could not copy libsecp256k1 dylib"

if [ ! -f "$DLL_TARGET_DIR/libzbar.0.dylib" ]; then
    info "Building ZBar dylib..."
    "$CONTRIB"/make_zbar.sh || fail "Could not build ZBar dylib"
else
    info "Skipping ZBar build: reusing already built dylib."
fi
cp -f "$DLL_TARGET_DIR/libzbar.0.dylib" "$PROJECT_ROOT/electrum/" || fail "Could not copy ZBar dylib"

if [ ! -f "$DLL_TARGET_DIR/libusb-1.0.dylib" ]; then
    info "Building libusb dylib..."
    "$CONTRIB"/make_libusb.sh || fail "Could not build libusb dylib"
else
    info "Skipping libusb build: reusing already built dylib."
fi
cp -f "$DLL_TARGET_DIR/libusb-1.0.dylib" "$PROJECT_ROOT/electrum/" || fail "Could not copy libusb dylib"


info "Installing requirements..."
python3 -m pip install --no-build-isolation --no-dependencies --no-binary :all: \
    --no-warn-script-location \
    -Ir ./contrib/deterministic-build/requirements.txt \
    || fail "Could not install requirements"

info "Installing hardware wallet requirements..."
python3 -m pip install --no-build-isolation --no-dependencies --no-binary :all: --only-binary cryptography \
    --no-warn-script-location \
    -Ir ./contrib/deterministic-build/requirements-hw.txt \
    || fail "Could not install hardware wallet requirements"

info "Installing dependencies specific to binaries..."
python3 -m pip install --no-build-isolation --no-dependencies --no-binary :all: --only-binary PyQt6,PyQt6-Qt6,cryptography \
    --no-warn-script-location \
    -Ir ./contrib/deterministic-build/requirements-binaries-mac.txt \
    || fail "Could not install dependencies specific to binaries"

info "Building $PACKAGE..."
python3 -m pip install --no-build-isolation --no-dependencies \
    --no-warn-script-location . > /dev/null || fail "Could not build $PACKAGE"
# pyinstaller needs to be able to "import electrum", for which we need libsecp256k1:
# (or could try "pip install -e" instead)
cp "$PROJECT_ROOT/electrum"/libsecp256k1.*.dylib "$VENV_DIR/lib/python$PY_VER_MAJOR/site-packages/electrum/"

# strip debug symbols of some compiled libs
# - hidapi (hid.cpython-39-darwin.so) in particular is not reproducible without this
find "$VENV_DIR/lib/python$PY_VER_MAJOR/site-packages/" -type f -name '*.so' -print0 \
    | xargs -0 -t strip -x

info "Faking timestamps..."
find . -exec touch -t '200101220000' {} + || true

VERSION=$(git describe --tags --dirty --always)

info "Building binary"
ELECTRUM_VERSION=$VERSION pyinstaller --noconfirm --clean contrib/osx/osx.spec || fail "Could not build binary"

info "Finished building unsigned dist/${PACKAGE}.app. This hash should be reproducible:"
find "dist/${PACKAGE}.app" -type f -print0 | sort -z | xargs -0 shasum -a 256 | shasum -a 256

info "Creating unsigned .DMG"
hdiutil create -fs HFS+ -volname $PACKAGE -srcfolder dist/$PACKAGE.app dist/electrum-$VERSION-unsigned.dmg || fail "Could not create .DMG"

info "App was built successfully but was not code signed. Users may get security warnings from macOS."
info "Now you also need to run sign_osx.sh to codesign/notarize the binary."
