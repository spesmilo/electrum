#!/bin/bash

PYINSTALLER_REPO="https://github.com/pyinstaller/pyinstaller.git"
PYINSTALLER_COMMIT="7c5dcd97a7679c5f3b04c43a0aae0ffeabe7462b"
# ^ tag "v6.15.0"

PYTHON_VERSION=3.12.10


# Let's begin!
set -e

here="$(dirname "$(readlink -e "$0")")"

. "$CONTRIB"/build_tools_util.sh

info "Booting wine."
wine 'wineboot'


cd "$CACHEDIR"
mkdir -p $WINEPREFIX/drive_c/tmp

info "Installing Python."
(
    if [ "$WIN_ARCH" = "win32" ] ; then
        PYARCH="win32"
    elif [ "$WIN_ARCH" = "win64" ] ; then
        PYARCH="amd64"
    else
        fail "unexpected WIN_ARCH: $WIN_ARCH"
    fi
    PYTHON_DOWNLOADS="$CACHEDIR/python$PYTHON_VERSION"
    mkdir -p "$PYTHON_DOWNLOADS"
    # - cpython parts: download
    for msifile in core dev exe lib pip; do
        download_if_not_exist "$PYTHON_DOWNLOADS/${msifile}.msi" "https://www.python.org/ftp/python/$PYTHON_VERSION/$PYARCH/${msifile}.msi"
    done
    # - cpython parts: verify hashes
    pushd "$PYTHON_DOWNLOADS"
    if [ "$WIN_ARCH" = "win32" ] ; then
        sha256sum -c - << EOF
7c2e1ca376f1a5007989af46241598f84a51fc19522aa23804859a44a251cb9c  core.msi
14f2edfc7fde03d2f85fc7c9040aa7076505cba341a22215a956c556266b1cb8  dev.msi
e5955351e72aa30bdd9bec18f7278e427ef50a2e93ace2ee57fa6b48760642b3  exe.msi
e7d656a11df18e6868fdd05127b7e87c0fb0b24e22aef28a70d5a169de76e563  lib.msi
7737dc9f406c6e2c0f8d06da7b9a5551885506fbdd6b3cbfa74bb8a3ba7df13d  pip.msi
EOF
        test $? -eq 0 || fail "unexpected hash for CPython parts"
    elif [ "$WIN_ARCH" = "win64" ] ; then
        sha256sum -c - << EOF
0075fe3c252b2af487443a7fbf666c8055e2d111ce7a75de7df0a5d45efb8794  core.msi
77b151b8d36f8bb4cde20ee6f0ff0681a2f88b2072ceac6abaa8e173f5a1eb78  dev.msi
64bef9bfc893cce8c697020fd4564a4e62c7f06e8f4b8ac3c5dfec37bdc56458  exe.msi
699b862a3a0330114f8ddae9b92e394b4ee93341ba90e19710982cae62cd4079  lib.msi
c508f2cbc48506a8ef518cb792c384bfa3634beae65cbfb2cf5f2a4ec1fca157  pip.msi
EOF
        test $? -eq 0 || fail "unexpected hash for CPython parts"
    else
        fail "unexpected WIN_ARCH: $WIN_ARCH"
    fi
    popd
    # - cpython parts: install
    for msifile in core dev exe lib pip; do
        wine msiexec /i "$PYTHON_DOWNLOADS/${msifile}.msi" /qb TARGETDIR=$WINE_PYHOME || fail "wine msiexec failed for ${msifile}.msi"
    done
)

break_legacy_easy_install

info "Installing build dependencies."
$WINE_PYTHON -m pip install --no-build-isolation --no-dependencies --no-warn-script-location \
    --cache-dir "$WINE_PIP_CACHE_DIR" -r "$CONTRIB"/deterministic-build/requirements-build-base.txt
$WINE_PYTHON -m pip install --no-build-isolation --no-dependencies --no-binary :all: --no-warn-script-location \
    --cache-dir "$WINE_PIP_CACHE_DIR" -r "$CONTRIB"/deterministic-build/requirements-build-wine.txt


# copy already built DLLs
cp "$DLL_TARGET_DIR"/*.dll "$WINEPREFIX/drive_c/electrum/electrum/" || fail "Could not copy DLLs to destination"


info "Building PyInstaller."
# we build our own PyInstaller boot loader as the default one has high
# anti-virus false positives
(
    if [ "$WIN_ARCH" = "win32" ] ; then
        PYINST_ARCH="32bit"
    elif [ "$WIN_ARCH" = "win64" ] ; then
        PYINST_ARCH="64bit"
    else
        fail "unexpected WIN_ARCH: $WIN_ARCH"
    fi
    if [ -f "$CACHEDIR/pyinstaller/PyInstaller/bootloader/Windows-$PYINST_ARCH-intel/runw.exe" ]; then
        info "pyinstaller already built, skipping"
        exit 0
    fi
    cd "$WINEPREFIX/drive_c/electrum"
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
    rm -fv PyInstaller/bootloader/Windows-*/run*.exe || true
    # add reproducible randomness. this ensures we build a different bootloader for each commit.
    # if we built the same one for all releases, that might also get anti-virus false positives
    echo "const char *electrum_tag = \"tagged by Electrum@$ELECTRUM_COMMIT_HASH\";" >> ./bootloader/src/pyi_main.c
    pushd bootloader
    # cross-compile to Windows using host python
    python3 ./waf all CC="${GCC_TRIPLET_HOST}-gcc" \
                      CFLAGS="-static"
    popd
    # sanity check bootloader is there:
    [[ -e "PyInstaller/bootloader/Windows-$PYINST_ARCH-intel/runw.exe" ]] || fail "Could not find runw.exe in target dir!"
)
info "Installing PyInstaller."
$WINE_PYTHON -m pip install --no-build-isolation --no-dependencies --no-warn-script-location ./pyinstaller

info "Wine is configured."
