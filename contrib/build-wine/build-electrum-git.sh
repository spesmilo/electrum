#!/bin/bash

NAME_ROOT=Electron-Cash
PYTHON_VERSION=3.5.4

CHECKOUT_TAG=3.3.5

# These settings probably don't need any change
export WINEPREFIX=/opt/wine64
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED=22

PYHOME=c:/python$PYTHON_VERSION
PYTHON="wine $PYHOME/python.exe -OO -B"


# Let's begin!
cd `dirname $0`
set -e

cd tmp


if [ -d electrum ]; then
    cd electrum
    git checkout master
    git pull
    cd ..
else
    URL=https://github.com/Electron-Cash/Electron-Cash
    git clone -b master $URL electrum # rest of script assumes the dir is called 'electrum'
fi

for repo in electrum-locale; do
    if [ -d $repo ]; then
        cd $repo
        git checkout master
        git pull
        cd ..
    else
        URL=https://github.com/Electron-Cash/$repo
        git clone -b master $URL $repo
    fi
done

pushd electrum-locale
for i in ./locale/*; do
    dir=$i/LC_MESSAGES
    mkdir -p $dir
    msgfmt --output-file=$dir/electron-cash.mo $i/electron-cash.po || true
done
popd


pushd electrum

if [ ! -z "$1" ]; then
    git checkout $1
else
    git checkout "$CHECKOUT_TAG"
fi

VERSION=`git describe --tags`
echo "Version to release: $VERSION"
find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd

rm -rf $WINEPREFIX/drive_c/electrum
cp -r electrum $WINEPREFIX/drive_c/electrum
cp electrum/LICENCE .
cp -r electrum-locale/locale $WINEPREFIX/drive_c/electrum/lib/


# Install frozen dependencies
$PYTHON -m pip install -r ../../deterministic-build/requirements.txt
$PYTHON -m pip install -r ../../deterministic-build/requirements-hw.txt

pushd $WINEPREFIX/drive_c/electrum
$PYTHON setup.py install
popd

cd ..

rm -rf dist/


# build standalone and portable versions
wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" --noconfirm --ascii --name $NAME_ROOT-$VERSION -w deterministic.spec


# set timestamps in dist, in order to make the installer reproducible
pushd dist
find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd


# build NSIS installer
# $VERSION could be passed to the electron-cash.nsi script, but this would require some rewriting in the script iself.
wine "$WINEPREFIX/drive_c/Program Files (x86)/NSIS/makensis.exe" /DPRODUCT_VERSION=$VERSION electron-cash.nsi

cd dist
mv Electron-Cash-setup.exe $NAME_ROOT-$VERSION-setup.exe

cd ../../..
if [ -d packages ] ; then
    python3 setup.py sdist --format=zip,gztar
else
    echo "Not creating source distribution since packages directory is missing."
    echo "Run './contrib/make_packages'"
    echo "Then you can run 'python3 setup.py sdist --format=zip,gztar'"
fi

echo "Done."
