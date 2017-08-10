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

#echo "add c:\MinGW\bin to PATH using regedit" in HKEY_CURRENT_USER/Environment
#regedit
#exit

#wine mingw-get install gcc
#wine mingw-get install mingw-utils
#wine mingw-get install mingw32-libz


#create cfg file
#printf "[build]\ncompiler=mingw32\n" > /opt/wine64/drive_c/Python27/Lib/distutils/distutils.cfg

# Install Cython
$PYTHON -m pip install setuptools --upgrade
$PYTHON -m pip install cython
$PYTHON -m pip install trezor
$PYTHON -m pip install keepkey
$PYTHON -m pip install btchip-python

#git clone https://github.com/trezor/cython-hidapi.git
#replace: from distutils.core import setup, Extenstion
#cd cython-hidapi
#git submodule init
#git submodule update
#$PYTHON setup.py install
#cd ..


