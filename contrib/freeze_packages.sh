#!/bin/bash
# Run this after a new release to update dependencies

venv_dir=~/.electron-cash-venv
contrib=$(dirname "$0")

which virtualenv > /dev/null 2>&1 || { echo "Please install virtualenv" && exit 1; }

# standard Electrum dependencies

rm "$venv_dir" -rf
virtualenv -p $(which python3) $venv_dir

source $venv_dir/bin/activate

echo "Installing main dependencies"

pushd $contrib/..
python setup.py install
popd

pip freeze | sed '/^Electron-Cash/ d' > $contrib/deterministic-build/requirements.txt

# hw wallet library dependencies

rm "$venv_dir" -rf
virtualenv -p $(which python3) $venv_dir

source $venv_dir/bin/activate

echo "Installing hw wallet dependencies"

python -m pip install -r $contrib/../requirements-hw.txt --upgrade

pip freeze | sed '/^Electron-Cash/ d' > $contrib/deterministic-build/requirements-hw.txt

echo "Done. Updated requirements"
