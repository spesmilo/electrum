#!/bin/bash

# Please update these links carefully, some versions won't work under Wine
PYTHON_URL=http://www.python.org/ftp/python/2.6.6/python-2.6.6.msi
PYQT4_URL=http://sourceforge.net/projects/pyqt/files/PyQt4/PyQt-4.9.5/PyQt-Py2.6-x86-gpl-4.9.5-1.exe
PYWIN32_URL=http://sourceforge.net/projects/pywin32/files/pywin32/Build%20218/pywin32-218.win32-py2.6.exe/download
PYINSTALLER_URL=http://downloads.sourceforge.net/project/pyinstaller/2.0/pyinstaller-2.0.zip
NSIS_URL=http://prdownloads.sourceforge.net/nsis/nsis-2.46-setup.exe?download
#ZBAR_URL=http://sourceforge.net/projects/zbar/files/zbar/0.10/zbar-0.10-setup.exe/download

# These settings probably don't need change
export WINEPREFIX=/opt/wine-electrum
PYHOME=c:/python26
PYTHON="wine $PYHOME/python.exe -OO -B"

# Let's begin!
cd `dirname $0`
set -e

# Clean up Wine environment
echo "Cleaning $WINEPREFIX"
rm -rf $WINEPREFIX/*
echo "done"

echo "Cleaning tmp"
rm -rf tmp
mkdir -p tmp
echo "done"

cd tmp

# Install Python
wget -O python.msi "$PYTHON_URL"
msiexec /q /i python.msi

# Install PyWin32
wget -O pywin32.exe "$PYWIN32_URL"
wine pywin32.exe

# Install PyQt4
wget -O PyQt.exe "$PYQT4_URL"
wine PyQt.exe

#cp -r /electrum-wine/pyinstaller $WINEPREFIX/drive_c/
# Install pyinstaller
wget -O pyinstaller.zip "$PYINSTALLER_URL"
unzip pyinstaller.zip
mv pyinstaller-2.0 $WINEPREFIX/drive_c/pyinstaller

# Patch pyinstaller's DummyZlib
patch $WINEPREFIX/drive_c/pyinstaller/PyInstaller/loader/archive.py < ../archive.patch

# Install ZBar
#wget -q -O zbar.exe "http://sourceforge.net/projects/zbar/files/zbar/0.10/zbar-0.10-setup.exe/download"
#wine zbar.exe

# Install dependencies
wget -q -O - "http://python-distribute.org/distribute_setup.py" | $PYTHON
wine "$PYHOME\\Scripts\\easy_install.exe" ecdsa slowaes ltc_scrypt #zbar

# Install NSIS installer
wget -q -O nsis.exe "http://prdownloads.sourceforge.net/nsis/nsis-2.46-setup.exe?download"
wine nsis.exe

# Install UPX
#wget -O upx.zip "http://upx.sourceforge.net/download/upx308w.zip"
#unzip -o upx.zip
#cp upx*/upx.exe .
