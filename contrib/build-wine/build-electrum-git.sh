#!/bin/bash

NAME_ROOT=electrum
PYTHON_VERSION=3.5.4

# These settings probably don't need any change
export WINEPREFIX=/opt/wine64
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED=22

PYHOME=c:/python$PYTHON_VERSION
PYTHON="wine $PYHOME/python.exe -OO -B"


# Let's begin!
cd `dirname $0`
set -e

mkdir -p tmp
cd tmp

if [ -d ./electrum ]; then
  rm ./electrum -rf
fi

git clone https://github.com/spesmilo/electrum -b master

pushd electrum
if [ ! -z "$1" ]; then
    # a commit/tag/branch was specified
    if ! git cat-file -e "$1" 2> /dev/null
    then  # can't find target
        # try pull requests
        git config --local --add remote.origin.fetch '+refs/pull/*/merge:refs/remotes/origin/pr/*'
        git fetch --all
    fi
    git checkout $1
fi

# Load electrum-icons and electrum-locale for this release
git submodule init
git submodule update

VERSION=`git describe --tags --dirty`
echo "Last commit: $VERSION"

pushd ./contrib/deterministic-build/electrum-locale
if ! which msgfmt > /dev/null 2>&1; then
    echo "Please install gettext"
    exit 1
fi
for i in ./locale/*; do
    dir=$i/LC_MESSAGES
    mkdir -p $dir
    msgfmt --output-file=$dir/electrum.mo $i/electrum.po || true
done
popd

find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd

rm -rf $WINEPREFIX/drive_c/electrum
cp -r electrum $WINEPREFIX/drive_c/electrum
cp electrum/LICENCE .
cp -r ./electrum/contrib/deterministic-build/electrum-locale/locale $WINEPREFIX/drive_c/electrum/lib/
cp ./electrum/contrib/deterministic-build/electrum-icons/icons_rc.py $WINEPREFIX/drive_c/electrum/gui/qt/

# Install frozen dependencies
$PYTHON -m pip install -r ../../deterministic-build/requirements.txt

$PYTHON -m pip install -r ../../deterministic-build/requirements-hw.txt

pushd $WINEPREFIX/drive_c/electrum
$PYTHON setup.py install
popd

cd ..

rm -rf dist/

# build standalone and portable versions
wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" --noconfirm --ascii --clean --name $NAME_ROOT-$VERSION -w deterministic.spec

# set timestamps in dist, in order to make the installer reproducible
pushd dist
find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd

# build NSIS installer
# $VERSION could be passed to the electrum.nsi script, but this would require some rewriting in the script itself.
wine "$WINEPREFIX/drive_c/Program Files (x86)/NSIS/makensis.exe" /DPRODUCT_VERSION=$VERSION electrum.nsi

cd dist
mv electrum-setup.exe $NAME_ROOT-$VERSION-setup.exe
cd ..

echo "Done."
md5sum dist/electrum*exe
