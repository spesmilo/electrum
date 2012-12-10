#!/bin/bash

# You probably need to update only this link
ELECTRUM_GIT_URL=git://github.com/spesmilo/electrum.git
BRANCH=master
NAME_ROOT=electrum-git

# These settings probably don't need any change
export WINEPREFIX=~/.wine-electrum
PYHOME=c:/python26
PYTHON="wine $PYHOME/python.exe -OO -B"

# Let's begin!
cd `dirname $0`
set -e

cd tmp

if [ -d "electrum-git" ]; then
    # GIT repository found, update it
    echo "Pull"

    cd electrum-git
    git pull
    cd ..

else
    # GIT repository not found, clone it
    echo "Clone"

    git clone -b $BRANCH $ELECTRUM_GIT_URL electrum-git
fi

rm -rf $WINEPREFIX/drive_c/electrum
cp -r electrum-git $WINEPREFIX/drive_c/electrum
cp electrum-git/LICENCE .

# Build Qt resources
wine $WINEPREFIX/drive_c/Python26/Lib/site-packages/PyQt4/pyrcc4.exe C:/electrum/icons.qrc -o C:/electrum/lib/icons_rc.py

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
