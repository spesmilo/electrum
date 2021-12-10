#!/bin/bash

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../../.."
CONTRIB="$PROJECT_ROOT/contrib"
CONTRIB_SDIST="$CONTRIB/build-linux/sdist"
DISTDIR="$PROJECT_ROOT/dist"
LOCALE="$PROJECT_ROOT/electrum/locale"

. "$CONTRIB"/build_tools_util.sh

# note that at least py3.7 is needed, to have https://bugs.python.org/issue30693
python3 --version || fail "python interpreter not found"

break_legacy_easy_install

# upgrade to modern pip so that it knows the flags we need.
# (make_packages will later install a pinned version of pip in a venv)
python3 -m pip install --upgrade pip

"$CONTRIB"/make_packages || fail "make_packages failed"

git submodule update --init

(
    # We include both source (.po) and compiled (.mo) locale files in the source dist.
    # Maybe we should exclude the compiled locale files? see https://askubuntu.com/a/144139
    # (also see MANIFEST.in)
    rm -rf "$LOCALE"
    cp -r "$CONTRIB/deterministic-build/electrum-locale/locale/" "$LOCALE/"
    "$CONTRIB/build_locale.sh" "$LOCALE"
)

(
    cd "$PROJECT_ROOT"

    find -exec touch -h -d '2000-11-11T11:11:11+00:00' {} +

    # note: .zip sdists would not be reproducible due to https://bugs.python.org/issue40963
    TZ=UTC faketime -f '2000-11-11 11:11:11' python3 setup.py --quiet sdist --format=gztar
)


info "done."
ls -la "$DISTDIR"
sha256sum "$DISTDIR"/*
