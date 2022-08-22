#!/bin/bash
# This script installs our pure python dependencies into the 'packages' folder.

set -e

CONTRIB="$(dirname "$(readlink -e "$0")")"
PROJECT_ROOT="$CONTRIB"/..
PACKAGES="$PROJECT_ROOT"/packages/

test -n "$CONTRIB" -a -d "$CONTRIB" || exit

if [ -d "$PACKAGES" ]; then
  rm -r "$PACKAGES"
fi

# create virtualenv
# note: venv path needs to be deterministic as some produced files will contain it
venv_dir="$CONTRIB/.venv_make_packages/"
rm -rf "$venv_dir"
python3 -m venv "$venv_dir"
source "$venv_dir"/bin/activate

# installing pinned build-time requirements, such as pip/wheel/setuptools
python -m pip install --no-build-isolation --no-dependencies --no-warn-script-location \
    -r "$CONTRIB"/deterministic-build/requirements-build-base.txt

# opt out of compiling C extensions
# FIXME aiohttp opt-out is not released yet: https://github.com/aio-libs/aiohttp/pull/3828
export AIOHTTP_NO_EXTENSIONS=1
export YARL_NO_EXTENSIONS=1
export MULTIDICT_NO_EXTENSIONS=1
export FROZENLIST_NO_EXTENSIONS=1

# if we end up having to compile something, at least give reproducibility a fighting chance
export LC_ALL=C
export TZ=UTC
export SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
export PYTHONHASHSEED="$SOURCE_DATE_EPOCH"
export BUILD_DATE="$(LC_ALL=C TZ=UTC date +'%b %e %Y' -d @$SOURCE_DATE_EPOCH)"
export BUILD_TIME="$(LC_ALL=C TZ=UTC date +'%H:%M:%S' -d @$SOURCE_DATE_EPOCH)"

# FIXME aiohttp will compile some .so files using distutils
#       (until https://github.com/aio-libs/aiohttp/pull/4079 gets released),
#       which are not reproducible unless using at least python 3.9
#       (as it needs https://github.com/python/cpython/commit/0d30ae1a03102de07758650af9243fd31211325a).
#       Hence "aiohttp-*.dist-info/" is not reproducible either.
#       All this means that downstream users of this script, such as the sdist build
#       and the android apk build need to make sure these files get excluded.
# note: --no-build-isolation is needed so that pip uses the locally available setuptools and wheel,
#       instead of downloading the latest ones
python3 -m pip install --no-build-isolation --no-compile --no-dependencies --no-binary :all: \
    -r "$CONTRIB"/deterministic-build/requirements.txt -t "$CONTRIB"/../packages
