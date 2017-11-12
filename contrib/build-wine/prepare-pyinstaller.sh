#!/bin/bash
PYTHON_VERSION=3.5.4

PYINSTALLER_GIT_URL=https://github.com/ecdsa/pyinstaller.git
BRANCH=fix_2952

export WINEPREFIX=/opt/wine64
PYHOME=c:/python$PYTHON_VERSION
PYTHON="wine $PYHOME/python.exe -OO -B"

cd `dirname $0`
set -e
cd tmp
if [ ! -d "pyinstaller" ]; then
    git clone -b $BRANCH $PYINSTALLER_GIT_URL pyinstaller
fi

cd pyinstaller
git pull
git checkout $BRANCH
$PYTHON setup.py install
cd ..

wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" -v
