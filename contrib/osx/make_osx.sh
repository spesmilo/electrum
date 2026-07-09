#!/usr/bin/env bash

set -e

# Parameterize
PYTHON_VERSION=3.12.10
PY_VER_MAJOR="3.12"  # as it appears in fs paths
PACKAGE=Electrum
GIT_REPO=https://github.com/spesmilo/electrum

export GCC_STRIP_BINARIES="1"
export PYTHONDONTWRITEBYTECODE=1  # don't create __pycache__/ folders with .pyc files


. "$(dirname "$0")/../build_tools_util.sh"


# Which CPU architecture to build for ("x86_64" or "arm64").
# Official release binaries for *both* targets are built on an x86_64 host;
# for the arm64 target we cross-compile. (see #7557)
ELECTRUM_MACOS_ARCH="${ELECTRUM_MACOS_ARCH:-x86_64}"
export ELECTRUM_MACOS_ARCH  # (also read by pyinstaller.spec)
case "$ELECTRUM_MACOS_ARCH" in
    x86_64)
        ARCH_DMG_SUFFIX=""
        ;;
    arm64)
        ARCH_DMG_SUFFIX="-arm64"
        ;;
    *)
        fail "unsupported ELECTRUM_MACOS_ARCH: '$ELECTRUM_MACOS_ARCH'. supported values: x86_64, arm64."
        ;;
esac


CONTRIB_OSX="$(dirname "$(realpath "$0")")"
CONTRIB="$CONTRIB_OSX/.."
PROJECT_ROOT="$CONTRIB/.."
CACHEDIR="$CONTRIB_OSX/.cache"
export DLL_TARGET_DIR="$CACHEDIR/dlls-$ELECTRUM_MACOS_ARCH"
PIP_CACHE_DIR="$CACHEDIR/pip_cache"

mkdir -p "$CACHEDIR" "$DLL_TARGET_DIR" "$PIP_CACHE_DIR"

cd "$PROJECT_ROOT"

git -C "$PROJECT_ROOT" rev-parse 2>/dev/null || fail "Building outside a git clone is not supported."


which brew > /dev/null 2>&1 || fail "Please install brew from https://brew.sh/ to continue"
which xcodebuild > /dev/null 2>&1 || fail "Please install xcode command line tools to continue"


info "Installing Python $PYTHON_VERSION"
PKG_FILE="python-${PYTHON_VERSION}-macos11.pkg"
if [ ! -f "$CACHEDIR/$PKG_FILE" ]; then
    curl -o "$CACHEDIR/$PKG_FILE" "https://www.python.org/ftp/python/${PYTHON_VERSION}/$PKG_FILE"
fi
echo "8373e58da4ea146b3eb1c1f9834f19a319440b6b679b06050b1f9ee3237aa8e4  $CACHEDIR/$PKG_FILE" | shasum -a 256 -c \
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
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# don't add debug info to compiled C files (e.g. when pip calls setuptools/wheel calls gcc)
# see https://github.com/pypa/pip/issues/6505#issuecomment-526613584
# note: this does not seem sufficient when cython is involved (although it is on linux, just not on mac... weird.)
#       see additional "strip" pass on built files later in the file.
export CFLAGS="-g0"

if [ "$ELECTRUM_MACOS_ARCH" = "arm64" ]; then
    # When targeting arm64, C extensions and dylibs are compiled as universal2 ("fat")
    # binaries, even though the app bundle will be arm64-only:
    # - pyinstaller must be able to *import* the modules on the (x86_64) build host
    #   during its Analysis step, so the host's slice is needed in the venv,
    # - the bundled app needs the arm64 slice.
    # pyinstaller thins all collected binaries to $ELECTRUM_MACOS_ARCH when
    # assembling the .app (see "target_arch" in pyinstaller.spec).
    export ARCHFLAGS="-arch x86_64 -arch arm64"
    # DYLIB_ARCHFLAGS is appended to CFLAGS for the libsecp256k1/zbar/libusb builds.
    DYLIB_ARCHFLAGS="-arch x86_64 -arch arm64"
    # libsecp's x86_64 asm cannot be compiled into the arm64 slice of a fat binary:
    LIBSECP_AUTOCONF_FLAGS="--with-asm=no"
else
    # Do not build universal binaries. The default on macos 11+ and xcode 12+ is "-arch arm64 -arch x86_64"
    # but with that e.g. "hid.cpython-310-darwin.so" is not reproducible as built by clang.
    export ARCHFLAGS="-arch x86_64"
    DYLIB_ARCHFLAGS=""
    LIBSECP_AUTOCONF_FLAGS=""
fi

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
    --cache-dir "$PIP_CACHE_DIR" -Ir ./contrib/deterministic-build/requirements-build-base.txt \
    || fail "Could not install build dependencies (base)"
python3 -m pip install --no-build-isolation --no-dependencies --no-binary :all: --no-warn-script-location \
    --cache-dir "$PIP_CACHE_DIR" -Ir ./contrib/deterministic-build/requirements-build-mac.txt \
    || fail "Could not install build dependencies (mac)"

info "Installing some build-time deps for compilation..."
brew install autoconf automake libtool gettext coreutils pkgconfig

info "Building PyInstaller."
PYINSTALLER_REPO="https://github.com/pyinstaller/pyinstaller.git"
PYINSTALLER_COMMIT="306d4d92580fea7be7ff2c89ba112cdc6f73fac1"
# ^ tag "v6.13.0"
(
    if [ -f "$CACHEDIR/pyinstaller/PyInstaller/bootloader/Darwin-64bit/runw" ] \
            && lipo "$CACHEDIR/pyinstaller/PyInstaller/bootloader/Darwin-64bit/runw" -verify_arch "$ELECTRUM_MACOS_ARCH" ; then
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
    # the bootloader is expected to be built as universal2 by default (see "--universal2"
    # in pyinstaller's bootloader/wscript). sanity check it contains the target arch:
    lipo "PyInstaller/bootloader/Darwin-64bit/runw" -verify_arch "$ELECTRUM_MACOS_ARCH" \
        || fail "bootloader was not built for $ELECTRUM_MACOS_ARCH. (xcode too old to build universal2 binaries?)"
)
info "Installing PyInstaller."
python3 -m pip install --no-build-isolation --no-dependencies \
    --cache-dir "$PIP_CACHE_DIR" --no-warn-script-location "$CACHEDIR/pyinstaller"

info "Using these versions for building $PACKAGE:"
sw_vers
python3 --version
echo -n "Pyinstaller "
pyinstaller --version

rm -rf ./dist

info "resetting git submodules."
# note: --force is less critical in other build scripts, but as the mac build is not doing a fresh clone,
#       it is very useful here for reproducibility
git submodule update --init --force

info "preparing electrum-locale."
(
    if ! which msgfmt > /dev/null 2>&1; then
        brew install gettext
        brew link --force gettext
    fi
    "$CONTRIB/locale/build_cleanlocale.sh"
    # we want the binary to have only compiled (.mo) locale files; not source (.po) files
    rm -r "$PROJECT_ROOT/electrum/locale/locale"/*/electrum.po
)


if ls "$DLL_TARGET_DIR"/libsecp256k1.*.dylib 1> /dev/null 2>&1; then
    info "libsecp256k1 already built, skipping"
else
    info "Building libsecp256k1 dylib..."
    CFLAGS="$CFLAGS $DYLIB_ARCHFLAGS" AUTOCONF_FLAGS="$LIBSECP_AUTOCONF_FLAGS" \
        "$CONTRIB"/make_libsecp256k1.sh || fail "Could not build libsecp"
fi
cp -f "$DLL_TARGET_DIR"/libsecp256k1.*.dylib "$PROJECT_ROOT/electrum" || fail "Could not copy libsecp256k1 dylib"

if [ ! -f "$DLL_TARGET_DIR/libzbar.0.dylib" ]; then
    info "Building ZBar dylib..."
    CFLAGS="$CFLAGS $DYLIB_ARCHFLAGS" "$CONTRIB"/make_zbar.sh || fail "Could not build ZBar dylib"
else
    info "Skipping ZBar build: reusing already built dylib."
fi
cp -f "$DLL_TARGET_DIR/libzbar.0.dylib" "$PROJECT_ROOT/electrum/" || fail "Could not copy ZBar dylib"

if [ ! -f "$DLL_TARGET_DIR/libusb-1.0.dylib" ]; then
    info "Building libusb dylib..."
    CFLAGS="$CFLAGS $DYLIB_ARCHFLAGS" "$CONTRIB"/make_libusb.sh || fail "Could not build libusb dylib"
else
    info "Skipping libusb build: reusing already built dylib."
fi
cp -f "$DLL_TARGET_DIR/libusb-1.0.dylib" "$PROJECT_ROOT/electrum/" || fail "Could not copy libusb dylib"


# opt out of compiling C extensions
export YARL_NO_EXTENSIONS=1
export PROPCACHE_NO_EXTENSIONS=1

export ELECTRUM_ECC_DONT_COMPILE=1

info "Installing requirements..."
python3 -m pip install --no-build-isolation --no-dependencies --no-binary :all: \
    --cache-dir "$PIP_CACHE_DIR" --no-warn-script-location \
    -Ir ./contrib/deterministic-build/requirements.txt \
    || fail "Could not install requirements"

info "Installing hardware wallet requirements..."
python3 -m pip install --no-build-isolation --no-dependencies --no-binary :all: --only-binary cryptography \
    --cache-dir "$PIP_CACHE_DIR" --no-warn-script-location \
    -Ir ./contrib/deterministic-build/requirements-hw.txt \
    || fail "Could not install hardware wallet requirements"

info "Installing dependencies specific to binaries..."
python3 -m pip install --no-build-isolation --no-dependencies --no-binary :all: --only-binary PyQt6,PyQt6-Qt6,cryptography \
    --cache-dir "$PIP_CACHE_DIR" --no-warn-script-location \
    -Ir ./contrib/deterministic-build/requirements-binaries-mac.txt \
    || fail "Could not install dependencies specific to binaries"

if [ "$ELECTRUM_MACOS_ARCH" = "arm64" ]; then
    # PyQt6-Qt6 does not ship universal2 wheels, only thin x86_64 and arm64 ones,
    # and pip installed the wheel matching the *build host*. Replace the Qt libs
    # with a universal2 merge of both thin wheels. (see make_universal_qt.py)
    info "Merging PyQt6-Qt6 x86_64+arm64 wheels into universal2 Qt libs..."
    python3 "$CONTRIB_OSX/make_universal_qt.py" \
        --requirements ./contrib/deterministic-build/requirements-binaries-mac.txt \
        --site-packages "$VENV_DIR/lib/python$PY_VER_MAJOR/site-packages" \
        --cache-dir "$CACHEDIR/qt_wheels" \
        || fail "Could not create universal2 Qt libs"
fi

info "Building $PACKAGE..."
python3 -m pip install --no-build-isolation --no-dependencies \
    --cache-dir "$PIP_CACHE_DIR" --no-warn-script-location . > /dev/null || fail "Could not build $PACKAGE"
# pyinstaller needs to be able to "import electrum_ecc", for which we need libsecp256k1:
# (or could try "pip install -e" instead)
cp "$DLL_TARGET_DIR"/libsecp256k1.*.dylib "$VENV_DIR/lib/python$PY_VER_MAJOR/site-packages/electrum_ecc/"

# strip debug symbols of some compiled libs
# - hidapi (hid.cpython-39-darwin.so) in particular is not reproducible without this
find "$VENV_DIR/lib/python$PY_VER_MAJOR/site-packages/" -type f -name '*.so' -print0 \
    | xargs -0 -t strip -x

info "Faking timestamps..."
find . -exec touch -t '200101220000' {} + || true

# note: no --dirty, as we have dirtied electrum/locale/ ourselves.
VERSION=$(git describe --tags --always)

info "Building binary"
ELECTRUM_VERSION=$VERSION pyinstaller --noconfirm --clean contrib/osx/pyinstaller.spec || fail "Could not build binary"

if [ "$ELECTRUM_MACOS_ARCH" = "arm64" ]; then
    # We compiled the venv binaries as universal2 (see ARCHFLAGS above) and rely on
    # pyinstaller to thin them. Sanity check every Mach-O file in the bundle is
    # thin and matches the target arch:
    info "Verifying architecture of Mach-O files in the app bundle..."
    find "dist/${PACKAGE}.app" -type f | while IFS= read -r f; do
        archs=$(lipo -archs "$f" 2>/dev/null) || continue  # not a Mach-O file
        if [ "$archs" != "$ELECTRUM_MACOS_ARCH" ]; then
            echo "unexpected architectures ('$archs') for file: $f"
            exit 1
        fi
    done || fail "app bundle contains files with unexpected architectures"
fi

info "Finished building unsigned dist/${PACKAGE}.app. This hash should be reproducible:"
find "dist/${PACKAGE}.app" -type f -print0 | sort -z | xargs -0 shasum -a 256 | shasum -a 256

info "Creating unsigned .DMG"
hdiutil create -fs HFS+ -volname $PACKAGE -srcfolder dist/$PACKAGE.app dist/electrum-${VERSION}${ARCH_DMG_SUFFIX}-unsigned.dmg || fail "Could not create .DMG"

info "App was built successfully but was not code signed. Users may get security warnings from macOS."
info "Now you also need to run sign_osx.sh to codesign/notarize the binary."
