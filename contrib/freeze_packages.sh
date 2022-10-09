#!/bin/bash
# Run this after a new release to update dependencies

set -e

venv_dir=~/.electrum-venv
contrib=$(dirname "$0")

# note: we should not use a higher version of python than what the binaries bundle
if [[ ! "$SYSTEM_PYTHON" ]] ; then
    SYSTEM_PYTHON=$(which python3.8) || printf ""
else
    SYSTEM_PYTHON=$(which $SYSTEM_PYTHON) || printf ""
fi
if [[ ! "$SYSTEM_PYTHON" ]] ; then
    echo "Please specify which python to use in \$SYSTEM_PYTHON" && exit 1
fi

which virtualenv > /dev/null 2>&1 || { echo "Please install virtualenv" && exit 1; }

${SYSTEM_PYTHON} -m hashin -h > /dev/null 2>&1 || { ${SYSTEM_PYTHON} -m pip install hashin; }

for i in '' '-hw' '-binaries' '-binaries-mac' '-build-wine' '-build-mac' '-build-base' '-build-appimage' '-build-android'; do
    rm -rf "$venv_dir"
    virtualenv -p ${SYSTEM_PYTHON} $venv_dir

    source $venv_dir/bin/activate

    echo "Installing dependencies... (requirements${i}.txt)"

    # We pin all python packaging tools (pip and friends). Some of our dependencies might
    # pull some of them in (e.g. protobuf->setuptools), and all transitive dependencies
    # must be pinned, so we might as well pin all packaging tools. This however means
    # that we should explicitly install them now, so that we pin latest versions if possible.
    python -m pip install --upgrade pip setuptools wheel

    python -m pip install -r "$contrib/requirements/requirements${i}.txt" --upgrade

    echo "OK."

    requirements=$(pip freeze --all)
    restricted=$(echo $requirements | ${SYSTEM_PYTHON} $contrib/deterministic-build/find_restricted_dependencies.py)
    requirements="$requirements $restricted"

    echo "Generating package hashes... (requirements${i}.txt)"
    rm "$contrib/deterministic-build/requirements${i}.txt"
    touch "$contrib/deterministic-build/requirements${i}.txt"

    for requirement in $requirements; do
        echo -e "\r  Hashing $requirement..."
        ${SYSTEM_PYTHON} -m hashin -r "$contrib/deterministic-build/requirements${i}.txt" "${requirement}"
    done

    echo "OK."
done

echo "Done. Updated requirements"
