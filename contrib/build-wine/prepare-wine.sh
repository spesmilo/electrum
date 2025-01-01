#!/bin/bash

PYINSTALLER_REPO="https://github.com/pyinstaller/pyinstaller.git"
PYINSTALLER_COMMIT="5d7a0449ecea400eccbbb30d5fcef27d72f8f75d"
# ^ tag "v6.6.0"

PYTHON_VERSION=3.11.9


# Let's begin!
set -e

here="$(dirname "$(readlink -e "$0")")"

. "$CONTRIB"/build_tools_util.sh

info "Booting wine."
wine 'wineboot'


cd "$CACHEDIR"
mkdir -p $WINEPREFIX/drive_c/tmp

info "Installing Python."
# note: you might need "sudo apt-get install dirmngr" for the following
# keys from https://www.python.org/downloads/#pubkeys
KEYRING_PYTHON_DEV="keyring-electrum-build-python-dev.gpg"
gpg --no-default-keyring --keyring $KEYRING_PYTHON_DEV --import "$here"/gpg_keys/7ED10B6531D7C8E1BC296021FC624643487034E5.asc
if [ "$WIN_ARCH" = "win32" ] ; then
    PYARCH="win32"
elif [ "$WIN_ARCH" = "win64" ] ; then
    PYARCH="amd64"
else
    fail "unexpected WIN_ARCH: $WIN_ARCH"
fi
PYTHON_DOWNLOADS="$CACHEDIR/python$PYTHON_VERSION"
mkdir -p "$PYTHON_DOWNLOADS"
for msifile in core dev exe lib pip tools; do
    echo "Installing $msifile..."
    download_if_not_exist "$PYTHON_DOWNLOADS/${msifile}.msi" "https://www.python.org/ftp/python/$PYTHON_VERSION/$PYARCH/${msifile}.msi"
    download_if_not_exist "$PYTHON_DOWNLOADS/${msifile}.msi.asc" "https://www.python.org/ftp/python/$PYTHON_VERSION/$PYARCH/${msifile}.msi.asc"
    verify_signature "$PYTHON_DOWNLOADS/${msifile}.msi.asc" $KEYRING_PYTHON_DEV || fail "invalid sig for ${msifile}.msi"
    wine msiexec /i "$PYTHON_DOWNLOADS/${msifile}.msi" /qb TARGETDIR=$WINE_PYHOME || fail "wine msiexec failed for ${msifile}.msi"
done

break_legacy_easy_install

info "Installing build dependencies."
$WINE_PYTHON -m pip install --no-build-isolation --no-dependencies --no-warn-script-location \
    --cache-dir "$WINE_PIP_CACHE_DIR" -r "$CONTRIB"/deterministic-build/requirements-build-base.txt
$WINE_PYTHON -m pip install --no-build-isolation --no-dependencies --no-binary :all: --no-warn-script-location \
    --cache-dir "$WINE_PIP_CACHE_DIR" -r "$CONTRIB"/deterministic-build/requirements-build-wine.txt


# copy already built DLLs
cp "$DLL_TARGET_DIR"/libsecp256k1-*.dll $WINEPREFIX/drive_c/electrum/electrum/ || fail "Could not copy libsecp to its destination"
cp "$DLL_TARGET_DIR/libzbar-0.dll" $WINEPREFIX/drive_c/electrum/electrum/ || fail "Could not copy libzbar to its destination"
cp "$DLL_TARGET_DIR/libusb-1.0.dll" $WINEPREFIX/drive_c/electrum/electrum/ || fail "Could not copy libusb to its destination"


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
) || fail "PyInstaller build failed"
info "Installing PyInstaller."
$WINE_PYTHON -m pip install --no-build-isolation --no-dependencies --no-warn-script-location ./pyinstaller

info "Wine is configured."
