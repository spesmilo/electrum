#!/bin/bash

# Please update these carefully, some versions won't work under Wine
NSIS_URL=https://prdownloads.sourceforge.net/nsis/nsis-3.02.1-setup.exe?download
NSIS_SHA256=736c9062a02e297e335f82252e648a883171c98e0d5120439f538c81d429552e
PYTHON_VERSION=3.5.4

## These settings probably don't need change
export WINEPREFIX=/opt/wine64
#export WINEARCH='win32'

PYHOME=c:/python$PYTHON_VERSION
PYTHON="wine $PYHOME/python.exe -OO -B"


# based on https://superuser.com/questions/497940/script-to-verify-a-signature-with-gpg
verify_signature() {
    local file=$1 keyring=$2 out=
    if out=$(gpg --no-default-keyring --keyring "$keyring" --status-fd 1 --verify "$file" 2>/dev/null) &&
       echo "$out" | grep -qs "^\[GNUPG:\] VALIDSIG "; then
        return 0
    else
        echo "$out" >&2
        exit 0
    fi
}

verify_hash() {
    local file=$1 expected_hash=$2 out=
    actual_hash=$(sha256sum $file | awk '{print $1}')
    if [ "$actual_hash" == "$expected_hash" ]; then
        return 0
    else
        echo "$file $actual_hash (unexpected hash)" >&2
        exit 0
    fi
}

# Let's begin!
cd `dirname $0`
set -e

# Clean up Wine environment
echo "Cleaning $WINEPREFIX"
rm -rf $WINEPREFIX
echo "done"

wine 'wineboot'

echo "Cleaning tmp"
rm -rf tmp
mkdir -p tmp
echo "done"

cd tmp

# Install Python
# note: you might need "sudo apt-get install dirmngr" for the following
# keys from https://www.python.org/downloads/#pubkeys
KEYRING_PYTHON_DEV=keyring-electrum-build-python-dev.gpg
gpg --no-default-keyring --keyring $KEYRING_PYTHON_DEV --recv-keys 531F072D39700991925FED0C0EDDC5F26A45C816 26DEA9D4613391EF3E25C9FF0A5B101836580288 CBC547978A3964D14B9AB36A6AF053F07D9DC8D2 C01E1CAD5EA2C4F0B8E3571504C367C218ADD4FF 12EF3DC38047DA382D18A5B999CDEA9DA4135B38 8417157EDBE73D9EAC1E539B126EB563A74B06BF DBBF2EEBF925FAADCF1F3FFFD9866941EA5BBD71 2BA0DB82515BBB9EFFAC71C5C9BE28DEE6DF025C 0D96DF4D4110E5C43FBFB17F2D347EA6AA65421D C9B104B3DD3AA72D7CCB1066FB9921286F5E1540 97FC712E4C024BBEA48A61ED3A5CA953F73C700D 7ED10B6531D7C8E1BC296021FC624643487034E5
for msifile in core dev exe lib pip tools; do
    echo "Installing $msifile..."
    wget "https://www.python.org/ftp/python/$PYTHON_VERSION/win32/${msifile}.msi"
    wget "https://www.python.org/ftp/python/$PYTHON_VERSION/win32/${msifile}.msi.asc"
    verify_signature "${msifile}.msi.asc" $KEYRING_PYTHON_DEV
    wine msiexec /i "${msifile}.msi" /qb TARGETDIR=C:/python$PYTHON_VERSION
done

# upgrade pip
$PYTHON -m pip install pip --upgrade

# Install PyWin32
$PYTHON -m pip install pypiwin32

# Install PyQt
$PYTHON -m pip install PyQt5

## Install pyinstaller
#$PYTHON -m pip install pyinstaller==3.3


# Install ZBar
#wget -q -O zbar.exe "https://sourceforge.net/projects/zbar/files/zbar/0.10/zbar-0.10-setup.exe/download"
#wine zbar.exe

# install Cryptodome
$PYTHON -m pip install pycryptodomex

# install PySocks
$PYTHON -m pip install win_inet_pton

# install websocket (python2)
$PYTHON -m pip install websocket-client

# Upgrade setuptools (so Electrum can be installed later)
$PYTHON -m pip install setuptools --upgrade

# Install NSIS installer
wget -q -O nsis.exe "$NSIS_URL"
verify_hash nsis.exe $NSIS_SHA256
wine nsis.exe /S

# Install UPX
#wget -O upx.zip "https://downloads.sourceforge.net/project/upx/upx/3.08/upx308w.zip"
#unzip -o upx.zip
#cp upx*/upx.exe .

# add dlls needed for pyinstaller:
cp $WINEPREFIX/drive_c/python$PYTHON_VERSION/Lib/site-packages/PyQt5/Qt/bin/* $WINEPREFIX/drive_c/python$PYTHON_VERSION/


# Install MinGW
wget http://downloads.sourceforge.net/project/mingw/Installer/mingw-get-setup.exe
wine mingw-get-setup.exe

echo "add c:\MinGW\bin to PATH using regedit"
echo "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
regedit

wine mingw-get install gcc
wine mingw-get install mingw-utils
wine mingw-get install mingw32-libz

printf "[build]\ncompiler=mingw32\n" > $WINEPREFIX/drive_c/python$PYTHON_VERSION/Lib/distutils/distutils.cfg

$PYTHON -m pip install scrypt

echo "Wine is configured. Please run prepare-pyinstaller.sh"
