#!/bin/bash

TREZOR_GIT_URL=https://github.com/trezor/python-trezor.git
KEEPKEY_GIT_URL=https://github.com/keepkey/python-keepkey.git
BTCHIP_GIT_URL=https://github.com/LedgerHQ/btchip-python.git

BRANCH=master

PYTHON_VERSION=3.5.4

# These settings probably don't need any change
export WINEPREFIX=/opt/wine64

PYHOME=c:/python$PYTHON_VERSION
PYTHON="wine $PYHOME/python.exe -OO -B"

# Let's begin!
cd `dirname $0`
set -e

cd tmp

$PYTHON -m pip install setuptools --upgrade
$PYTHON -m pip install cython --upgrade
$PYTHON -m pip install trezor==0.7.16 --upgrade
$PYTHON -m pip install keepkey==4.0.2 --upgrade
$PYTHON -m pip install btchip-python==0.1.24 --upgrade

