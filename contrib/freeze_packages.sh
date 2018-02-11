#!/bin/bash
# Run this after a new release to update dependencies

venv_dir=~/.electrum-venv
contrib=$(dirname "$0")

which virtualenv > /dev/null 2>&1 || { echo "Please install virtualenv" && exit 1; }

for i in '' '-hw' '-binaries'; do
    rm "$venv_dir" -rf
    virtualenv -p $(which python3) $venv_dir

    source $venv_dir/bin/activate

    echo "Installing $i dependencies"

    python -m pip install -r $contrib/requirements/requirements${i}.txt --upgrade

    pip freeze | sed '/^Electrum/ d' > $contrib/deterministic-build/requirements${i}.txt
done

echo "Done. Updated requirements"
