#!/bin/bash
# Run this after a new release to update dependencies

venv_dir=~/.electrum-venv
contrib=$(dirname "$0")

which virtualenv > /dev/null 2>&1 || { echo "Please install virtualenv" && exit 1; }
python3 -m hashin -h > /dev/null 2>&1 || { python3 -m pip install hashin; }
other_python=$(which python3)

for i in '' '-hw' '-binaries'; do
    rm -rf "$venv_dir"
    virtualenv -p $(which python3) $venv_dir

    source $venv_dir/bin/activate

    echo "Installing $m dependencies"

    python -m pip install -r $contrib/requirements/requirements${i}.txt --upgrade

    echo "OK."

    requirements=$(pip freeze --all)
    restricted=$(echo $requirements | $other_python $contrib/deterministic-build/find_restricted_dependencies.py)
    requirements="$requirements $restricted"

    echo "Generating package hashes..."
    rm $contrib/deterministic-build/requirements${i}.txt
    touch $contrib/deterministic-build/requirements${i}.txt

    for requirement in $requirements; do
        echo -e "\r  Hashing $requirement..."
        $other_python -m hashin -r $contrib/deterministic-build/requirements${i}.txt ${requirement}
    done

    echo "OK."
done

echo "Done. Updated requirements"
