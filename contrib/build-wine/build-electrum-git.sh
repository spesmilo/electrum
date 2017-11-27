#!/bin/bash

NAME_ROOT=electrum
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

for repo in electrum electrum-locale electrum-icons; do
    if [ -d $repo ]; then
	cd $repo
	git pull
	git checkout master
	cd ..
    else
	URL=https://github.com/spesmilo/$repo.git
	git clone -b master $URL $repo
    fi
done

pushd electrum-locale
for i in ./locale/*; do
    dir=$i/LC_MESSAGES
    mkdir -p $dir
    msgfmt --output-file=$dir/electrum.mo $i/electrum.po || true
done
popd

pushd electrum-git
VERSION=`git describe --tags`
echo "Last commit: $VERSION"
popd

rm -rf $WINEPREFIX/drive_c/electrum
cp -r electrum $WINEPREFIX/drive_c/electrum
cp electrum/LICENCE .
cp -r electrum-locale/locale $WINEPREFIX/drive_c/electrum/lib/
cp electrum-icons/icons_rc.py $WINEPREFIX/drive_c/electrum/gui/qt/

# Install frozen dependencies
$PYTHON -m pip install -r ../../deterministic_requirements.txt

pushd $WINEPREFIX/drive_c/electrum
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
mv electrum-setup.exe $NAME_ROOT-$VERSION-setup.exe
cd ..

# build portable version
cp portable.patch $WINEPREFIX/drive_c/electrum
pushd $WINEPREFIX/drive_c/electrum
patch < portable.patch 
popd
wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" --noconfirm --ascii --name $NAME_ROOT-$VERSION-portable.exe -w deterministic.spec

echo "Done."
