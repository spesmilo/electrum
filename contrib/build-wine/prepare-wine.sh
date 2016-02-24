#!/bin/bash

# Please update these links carefully, some versions won't work under Wine
PYTHON_URL=http://www.python.org/ftp/python/2.7.8/python-2.7.8.msi
PYQT4_URL=http://sourceforge.net/projects/pyqt/files/PyQt4/PyQt-4.11.1/PyQt4-4.11.1-gpl-Py2.7-Qt4.8.6-x32.exe
PYWIN32_URL=http://sourceforge.net/projects/pywin32/files/pywin32/Build%20219/pywin32-219.win32-py2.7.exe/download
PYINSTALLER_URL=https://pypi.python.org/packages/source/P/PyInstaller/PyInstaller-2.1.zip
NSIS_URL=http://prdownloads.sourceforge.net/nsis/nsis-2.46-setup.exe?download
SETUPTOOLS_URL=https://pypi.python.org/packages/2.7/s/setuptools/setuptools-0.6c11.win32-py2.7.exe


## These settings probably don't need change
export WINEPREFIX=/opt/wine64
#export WINEARCH='win32'

PYHOME=c:/python27
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
wget -O python.msi "$PYTHON_URL"
wine msiexec /q /i python.msi

# Install PyWin32
wget -O pywin32.exe "$PYWIN32_URL"
wine pywin32.exe

# Install PyQt4
wget -O PyQt.exe "$PYQT4_URL"
wine PyQt.exe

# Install pyinstaller
wget -O pyinstaller.zip "$PYINSTALLER_URL"
unzip pyinstaller.zip
mv PyInstaller-2.1 $WINEPREFIX/drive_c/pyinstaller

# Install ZBar
#wget -q -O zbar.exe "http://sourceforge.net/projects/zbar/files/zbar/0.10/zbar-0.10-setup.exe/download"
#wine zbar.exe

# Install setuptools
wget -O setuptools.exe "$SETUPTOOLS_URL"
wine setuptools.exe

# Install NSIS installer
wget -q -O nsis.exe "$NSIS_URL"
wine nsis.exe

# Install UPX
#wget -O upx.zip "http://upx.sourceforge.net/download/upx308w.zip"
#unzip -o upx.zip
#cp upx*/upx.exe .

# add dlls needed for pyinstaller:
cp $WINEPREFIX/drive_c/windows/system32/msvcp90.dll $WINEPREFIX/drive_c/Python27/
cp $WINEPREFIX/drive_c/windows/system32/msvcm90.dll $WINEPREFIX/drive_c/Python27/
