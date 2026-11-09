#!/bin/bash

PYINSTALLER_REPO="https://github.com/pyinstaller/pyinstaller.git"
PYINSTALLER_COMMIT="7c5dcd97a7679c5f3b04c43a0aae0ffeabe7462b"
# ^ tag "v6.15.0"

PYTHON_VERSION=3.14.10


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
b22517eb15e621a3b35e642c2f4be8b348c07ea2f2b607520cceb9dfad23ed32  core.msi
1a59029e104fb3d3dc4b95c2655c252067eb9aaeb066c130bdc5054d99eefd6d  dev.msi
e1365f93fc1b5a5acd6dca3a9d8eb2b5391952227f40ef01ff6cba9672ba453d  exe.msi
c6b62c71e8dbdbae09eb28d437549f1e881a0ebeff10d032c16065e2ba25364f  lib.msi
799fe09be0116c7607450626db19496fd82a7ff2a29fefb1d182c454e535e909  pip.msi
EOF
        test $? -eq 0 || fail "unexpected hash for CPython parts"
    elif [ "$WIN_ARCH" = "win64" ] ; then
        sha256sum -c - << EOF
c281a45a6f32d09f5964c6c46e9438ac11a578949ae50b486f8a7e3077190171  core.msi
cae457dd9581e8546c942ddcb370c183b1b7e77d53bb8d190a6f7daece3d8a2a  dev.msi
020fe726f23828d705fea820613f7f6806d94a25fa765ad1cd3edd6d4c8a118a  exe.msi
b1af18657af9de511c8c66dfc5ab8e89965c95339cc759c3d0733a8eab6a14fc  lib.msi
ace2b7d2c6fcda57c19947128a1ee7e1a8e4a585ca4e6a4ba25401bb9db69d35  pip.msi
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
