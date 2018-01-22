#!/bin/bash
# Run this after a new release to update dependencies

venv_dir=~/.electon-cash-venv
contrib=$(dirname "$0")

which virtualenv3 > /dev/null 2>&1 || { echo "Please install virtualenv3" && exit 1; }

rm $venv_dir -rf
virtualenv3 $venv_dir

source $venv_dir/bin/activate

echo "Installing dependencies"

pushd $contrib/..
python setup.py install
popd

pip freeze | sed '/^Electron-Cash/ d' > $contrib/requirements.txt

echo "Updated requirements"
