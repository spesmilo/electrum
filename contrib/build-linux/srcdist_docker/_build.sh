#!/bin/bash

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../../.."
CONTRIB="$PROJECT_ROOT/contrib"
DISTDIR="$PROJECT_ROOT/dist"

export GCC_STRIP_BINARIES="1"
export GIT_SUBMODULE_FLAGS="--recommend-shallow --depth 1"

. "$CONTRIB"/base.sh

rm -fvr "$DISTDIR"
mkdir -p "$DISTDIR"

python3 --version || fail "No python"

pushd $PROJECT_ROOT

info "Setting up Python venv ..."
python3 -m venv env
source env/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade setuptools
python3 -m pip install --upgrade requests

# the below prints its own info message
contrib/make_linux_sdist

popd
