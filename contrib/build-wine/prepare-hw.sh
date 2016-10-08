#!/bin/bash

TREZOR_GIT_URL=git://github.com/trezor/python-trezor.git
KEEPKEY_GIT_URL=git://github.com/keepkey/python-keepkey.git
BTCHIP_GIT_URL=git://github.com/LedgerHQ/btchip-python.git

BRANCH=master

# These settings probably don't need any change
export WINEPREFIX=/opt/wine64

PYHOME=c:/python27
PYTHON="wine $PYHOME/python.exe "

# Let's begin!
cd `dirname $0`
set -e

cd tmp

# downoad mingw-get-setup.exe
#wget http://downloads.sourceforge.net/project/mingw/Installer/mingw-get-setup.exe
#wine mingw-get-setup.exe

#echo "add c:\MinGW\bin to PATH using regedit"
#regedit
#exit

#wine mingw-get install gcc
#wine mingw-get install mingw-utils
#wine mingw-get install mingw32-libz

#create cfg file
#printf "[build]\ncompiler=mingw32\n" > /opt/me/wine64/drive_c/Python27/Lib/distutils/distutils.cfg

# Install Cython
#wine "$PYHOME\\Scripts\\easy_install.exe" cython


# not working
##wine "$PYHOME\\Scripts\\easy_install.exe" hidapi

#git clone https://github.com/trezor/cython-hidapi.git

#replace: from distutils.core import setup, Extenstion

#cd cython-hidapi
#git submodule init
#git submodule update
#$PYTHON setup.py install
#cd ..

# trezor
if ! [ -d "trezor-0.7.4" ]; then
    wget "https://pypi.python.org/packages/16/f1/e30d601857ab48f80ab73d15cda957528b5fa3b90bd8168f1e5a1fdd5b1d/trezor-0.7.4.tar.gz"
    tar -xvzf trezor-0.7.4.tar.gz
fi
cd trezor-0.7.4
$PYTHON setup.py install
cd ..

#keepkey
if [ -d "keepkey-git" ]; then
    cd keepkey-git
    git checkout master
    git pull
    cd ..
else
    git clone -b $BRANCH $KEEPKEY_GIT_URL keepkey-git
fi
cd keepkey-git
# checkout 2 commits before v0.7.3, because it fails to build
# git checkout v0.7.3
git checkout 7abe0f0c9026907e9a8db1d231e084df2c175817
$PYTHON setup.py install
cd ..

#btchip
if [ -d "btchip-git" ]; then
    cd btchip-git
    git checkout master
    git pull
    cd ..
else
    git clone -b $BRANCH $BTCHIP_GIT_URL btchip-git
fi
cd btchip-git
$PYTHON setup.py install
cd ..

