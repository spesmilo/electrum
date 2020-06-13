#!/bin/bash
# Run this after a new release to update dependencies

set -e

venv_dir=~/.electrum-venv
contrib=$(dirname "$0")

# note: we should not use a higher version of python than what the binaries bundle
if [[ ! "$SYSTEM_PYTHON" ]] ; then
    SYSTEM_PYTHON=$(which python3.6) || printf ""
else
    SYSTEM_PYTHON=$(which $SYSTEM_PYTHON) || printf ""
fi
if [[ ! "$SYSTEM_PYTHON" ]] ; then
    echo "Please specify which python to use in \$SYSTEM_PYTHON" && exit 1;
fi

which virtualenv > /dev/null 2>&1 || { echo "Please install virtualenv" && exit 1; }

${SYSTEM_PYTHON} -m hashin -h > /dev/null 2>&1 || { ${SYSTEM_PYTHON} -m pip install hashin; }

for i in '' '-hw' '-binaries' '-wine-build' '-mac-build' '-sdist-build'; do
    rm -rf "$venv_dir"
    virtualenv -p ${SYSTEM_PYTHON} $venv_dir

    source $venv_dir/bin/activate

    echo "Installing $m dependencies"

    python -m pip install -r $contrib/requirements/requirements${i}.txt --upgrade

    echo "OK."

    requirements=$(pip freeze --all)
    restricted=$(echo $requirements | ${SYSTEM_PYTHON} $contrib/deterministic-build/find_restricted_dependencies.py)
    requirements="$requirements $restricted"

    echo "Generating package hashes..."
    rm $contrib/deterministic-build/requirements${i}.txt
    touch $contrib/deterministic-build/requirements${i}.txt

    for requirement in $requirements; do
        echo -e "\r  Hashing $requirement..."
        ${SYSTEM_PYTHON} -m hashin -r $contrib/deterministic-build/requirements${i}.txt ${requirement}
    done

    echo "OK."
done

echo "Done. Updated requirements"
