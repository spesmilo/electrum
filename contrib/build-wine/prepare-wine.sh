#!/bin/bash

# Please update these carefully, some versions won't work under Wine
NSIS_URL=http://prdownloads.sourceforge.net/nsis/nsis-3.02.1-setup.exe?download
PYTHON_VERSION=3.5.4

## These settings probably don't need change
export WINEPREFIX=/opt/wine64
#export WINEARCH='win32'

PYHOME=c:/python$PYTHON_VERSION
PYTHON="wine $PYHOME/python.exe -OO -B"

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
for msifile in core dev exe lib pip tools; do
    echo "Installing $msifile..."
    wget "https://www.python.org/ftp/python/$PYTHON_VERSION/win32/${msifile}.msi"
    wine msiexec /i "${msifile}.msi" /qb TARGETDIR=C:/python$PYTHON_VERSION
done

# upgrade pip
$PYTHON -m pip install pip --upgrade

# Install PyWin32
$PYTHON -m pip install pypiwin32

# Install PyQt
$PYTHON -m pip install PyQt5

# Install pyinstaller
$PYTHON -m pip install pyinstaller==3.2.1

# Install ZBar
#wget -q -O zbar.exe "http://sourceforge.net/projects/zbar/files/zbar/0.10/zbar-0.10-setup.exe/download"
#wine zbar.exe

# install Cryptodome
$PYTHON -m pip install pycryptodomex

# install PySocks
$PYTHON -m pip install win_inet_pton

# install websocket (python2)
$PYTHON -m pip install websocket-client


# Install setuptools
#wget -O setuptools.exe "$SETUPTOOLS_URL"
#wine setuptools.exe

# Upgrade setuptools (so Electrum can be installed later)
$PYTHON -m pip install setuptools --upgrade

# Install NSIS installer
echo "Make sure to untick 'Start NSIS' and 'Show release notes'" 
wget -q -O nsis.exe "$NSIS_URL"
wine nsis.exe

# Install UPX
#wget -O upx.zip "http://upx.sourceforge.net/download/upx308w.zip"
#unzip -o upx.zip
#cp upx*/upx.exe .

# add dlls needed for pyinstaller:
cp $WINEPREFIX/drive_c/windows/system32/msvcp90.dll $WINEPREFIX/drive_c/python$PYTHON_VERSION/
cp $WINEPREFIX/drive_c/windows/system32/msvcm90.dll $WINEPREFIX/drive_c/python$PYTHON_VERSION/
cp $WINEPREFIX/drive_c/python$PYTHON_VERSION/Lib/site-packages/PyQt5/Qt/bin/* $WINEPREFIX/drive_c/python$PYTHON_VERSION/
