#!/bin/bash
# Run this after a new release to update dependencies

set -e

venv_dir=~/.electrum-venv
contrib="$(dirname "$0")"

# note: we should not use a higher version of python than what the binaries bundle
if [[ ! "$SYSTEM_PYTHON" ]] ; then
    SYSTEM_PYTHON=$(which python3.10) || printf ""
else
    SYSTEM_PYTHON=$(which "$SYSTEM_PYTHON") || printf ""
fi
if [[ ! "$SYSTEM_PYTHON" ]] ; then
    echo "Please specify which python to use in \$SYSTEM_PYTHON" && exit 1
fi

"${SYSTEM_PYTHON}" -m hashin -h > /dev/null 2>&1 || { "${SYSTEM_PYTHON}" -m pip install hashin; }

for suffix in '' '-hw' '-binaries' '-binaries-mac' '-build-wine' '-build-mac' '-build-base' '-build-appimage' '-build-android'; do
    reqfile="requirements${suffix}.txt"

    rm -rf "$venv_dir"
    "${SYSTEM_PYTHON}" -m venv "$venv_dir"

    source "$venv_dir/bin/activate"

    echo "Installing dependencies... (${reqfile})"

    # We pin all python packaging tools (pip and friends). Some of our dependencies might
    # pull some of them in (e.g. protobuf->setuptools), and all transitive dependencies
    # must be pinned, so we might as well pin all packaging tools. This however means
    # that we should explicitly install them now, so that we pin latest versions if possible.
    python -m pip install --upgrade pip setuptools wheel

    # install ghost packages to satisfy dependency resolvers
    for package in $(cat "$contrib/requirements/ghost.txt"); do
        python "$contrib/install_ghost.py" "$package"
    done

    python -m pip install -r "$contrib/requirements/${reqfile}" --upgrade

    echo "OK."

    requirements=$(pip freeze --all)

    restricted=$(echo $requirements | python "$contrib/deterministic-build/find_restricted_dependencies.py")
    if [ ! -z "$restricted" ]; then
        python -m pip install $restricted
    fi

    echo "Generating package hashes... (${reqfile})"
    rm -f "$contrib/deterministic-build/${reqfile}"
    touch "$contrib/deterministic-build/${reqfile}"

    # restrict ourselves to source-only packages.
    # TODO expand this to all reqfiles...
    HASHIN_FLAGS=""
    if [[
        "${suffix}" == "" ||
        "${suffix}" == "-build-wine" ||
        "${suffix}" == "-build-mac" ||
        "${suffix}" == "-build-appimage" ||
        "${suffix}" == "-build-android" ||
        "0" == "1"
        ]] ;
    then
        HASHIN_FLAGS="--python-version source"
    fi

    # remove ghost packages before hashin step, so that they aren't hashed
    for package in $(cat "$contrib/requirements/ghost.txt"); do
        python -m pip uninstall -y $package
    done
    requirements=$(pip freeze --all)

    echo -e "\r  Hashing requirements for $reqfile..."
    ${SYSTEM_PYTHON} -m hashin $HASHIN_FLAGS -r "$contrib/deterministic-build/${reqfile}" $requirements

    echo "OK."
done

echo "Done. Updated requirements"
