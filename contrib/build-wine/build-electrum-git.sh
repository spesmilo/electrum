#!/bin/bash

# You probably need to update only this link
ELECTRUM_GIT_URL=https://github.com/pooler/electrum-ltc.git
BRANCH=master
NAME_ROOT=electrum-ltc
PYTHON_VERSION=3.5.4

if [ "$#" -gt 0 ]; then
    BRANCH="$1"
fi

# These settings probably don't need any change
export WINEPREFIX=/opt/wine64
export PYTHONHASHSEED=22


PYHOME=c:/python$PYTHON_VERSION
PYTHON="wine $PYHOME/python.exe -OO -B"


# Let's begin!
cd `dirname $0`
set -e

cd tmp

if [ -d "electrum-ltc-git" ]; then
    # GIT repository found, update it
    echo "Pull"
    cd electrum-ltc-git
    git pull
    git checkout $BRANCH
    cd ..
else
    # GIT repository not found, clone it
    echo "Clone"
    git clone -b $BRANCH $ELECTRUM_GIT_URL electrum-ltc-git
fi

cd electrum-ltc-git
VERSION=`git describe --tags`
echo "Last commit: $VERSION"

cd ..

rm -rf $WINEPREFIX/drive_c/electrum-ltc
cp -r electrum-ltc-git $WINEPREFIX/drive_c/electrum-ltc
cp electrum-ltc-git/LICENCE .

# add locale dir
cp -r ../../../lib/locale $WINEPREFIX/drive_c/electrum-ltc/lib/

# Build Qt resources
wine $WINEPREFIX/drive_c/python$PYTHON_VERSION/Scripts/pyrcc5.exe C:/electrum-ltc/icons.qrc -o C:/electrum-ltc/gui/qt/icons_rc.py


pushd $WINEPREFIX/drive_c/electrum-ltc
$PYTHON setup.py install
popd

cd ..

rm -rf dist/

# build standalone version
wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" --noconfirm --ascii --name $NAME_ROOT-$VERSION.exe -w deterministic.spec 

# build NSIS installer
# $VERSION could be passed to the electrum.nsi script, but this would require some rewriting in the script iself.
wine "$WINEPREFIX/drive_c/Program Files (x86)/NSIS/makensis.exe" /DPRODUCT_VERSION=$VERSION electrum.nsi

cd dist
mv electrum-ltc-setup.exe $NAME_ROOT-$VERSION-setup.exe
cd ..

# build portable version
cp portable.patch $WINEPREFIX/drive_c/electrum-ltc
pushd $WINEPREFIX/drive_c/electrum-ltc
patch < portable.patch 
popd
wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" --noconfirm --ascii --name $NAME_ROOT-$VERSION-portable.exe -w deterministic.spec

echo "Done."
