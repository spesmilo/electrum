#!/bin/bash

# call "./build-wine.sh" to build everything from scratch
# call "./build-wine.sh update" to skip building full environment (it re-download only Electrum)

# You probably need to update only this link
ELECTRUM_URL=https://github.com/downloads/spesmilo/electrum/Electrum-1.5.6.tar.gz
NAME_ROOT=electrum-1.5.6

# Please update these links carefully, some versions won't work under Wine
PYTHON_URL=http://www.python.org/ftp/python/2.6.6/python-2.6.6.msi
PYQT4_URL=http://sourceforge.net/projects/pyqt/files/PyQt4/PyQt-4.9.5/PyQt-Py2.6-x86-gpl-4.9.5-1.exe
PYWIN32_URL=http://sourceforge.net/projects/pywin32/files/pywin32/Build%20218/pywin32-218.win32-py2.6.exe/download
PYINSTALLER_URL=https://github.com/downloads/pyinstaller/pyinstaller/pyinstaller-2.0.zip
NSIS_URL=http://prdownloads.sourceforge.net/nsis/nsis-2.46-setup.exe?download
#ZBAR_URL=http://sourceforge.net/projects/zbar/files/zbar/0.10/zbar-0.10-setup.exe/download

# These settings probably don't need change
export WINEPREFIX=~/.wine-electrum
PYHOME=c:/python26
PYTHON="wine $PYHOME/python.exe -OO -B"

# Let's begin!
cd `dirname $0`
set -e

if [ "x$1" != "xupdate" ]; then

    # Clean Wine environment
    echo "Cleaning $WINEPREFIX"
    rm -rf $WINEPREFIX
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
    wine "$PYHOME\\Scripts\\easy_install.exe" ecdsa slowaes #zbar

    # Install NSIS installer
    wget -q -O nsis.exe "http://prdownloads.sourceforge.net/nsis/nsis-2.46-setup.exe?download"
    wine nsis.exe

    # Install UPX
    #wget -O upx.zip "http://upx.sourceforge.net/download/upx308w.zip"
    #unzip -o upx.zip
    #cp upx*/upx.exe .
 
    cd ..
fi

cd tmp

# Download and unpack Electrum
wget -O electrum.tgz "$ELECTRUM_URL"
tar xf electrum.tgz
mv Electrum-* electrum
rm -rf $WINEPREFIX/drive_c/electrum
mv electrum $WINEPREFIX/drive_c

# Copy ZBar libraries to electrum    
#cp "$WINEPREFIX/drive_c/Program Files (x86)/ZBar/bin/"*.dll "$WINEPREFIX/drive_c/electrum/"

cd ..

rm -rf dist/$NAME_ROOT
rm -f dist/$NAME_ROOT.zip
rm -f dist/$NAME_ROOT.exe
rm -f dist/$NAME_ROOT-setup.exe

# For building standalone compressed EXE, run:
$PYTHON "C:/pyinstaller/pyinstaller.py" --noconfirm --ascii -w --onefile "C:/electrum/electrum"

# For building uncompressed directory of dependencies, run:
$PYTHON "C:/pyinstaller/pyinstaller.py" --noconfirm --ascii -w deterministic.spec

# For building NSIS installer, run:
wine "$WINEPREFIX/drive_c/Program Files (x86)/NSIS/makensis.exe" electrum.nsis
#wine $WINEPREFIX/drive_c/Program\ Files\ \(x86\)/NSIS/makensis.exe electrum.nsis

cd dist
mv electrum.exe $NAME_ROOT.exe
mv electrum $NAME_ROOT
mv electrum-setup.exe $NAME_ROOT-setup.exe
zip -r $NAME_ROOT.zip $NAME_ROOT
