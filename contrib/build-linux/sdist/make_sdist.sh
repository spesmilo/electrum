#!/bin/bash

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../../.."
CONTRIB="$PROJECT_ROOT/contrib"
CONTRIB_SDIST="$CONTRIB/build-linux/sdist"
DISTDIR="$PROJECT_ROOT/dist"
LOCALE="$PROJECT_ROOT/electrum/locale"

. "$CONTRIB"/build_tools_util.sh

git -C "$PROJECT_ROOT" rev-parse 2>/dev/null || fail "Building outside a git clone is not supported."

# note that at least py3.7 is needed, to have https://bugs.python.org/issue30693
python3 --version || fail "python interpreter not found"

break_legacy_easy_install

# upgrade to modern pip so that it knows the flags we need.
# (make_packages.sh will later install a pinned version of pip in a venv)
python3 -m pip install --upgrade pip

rm -rf "$PROJECT_ROOT/packages/"
if ([ "$OMIT_UNCLEAN_FILES" != 1 ]); then
    "$CONTRIB"/make_packages.sh || fail "make_packages failed"
fi

git submodule update --init

(
    # By default, include both source (.po) and compiled (.mo) locale files in the source dist.
    # Set option OMIT_UNCLEAN_FILES=1 to exclude the compiled locale files
    # see https://askubuntu.com/a/144139 (also see MANIFEST.in)
    rm -rf "$LOCALE"
    cp -r "$CONTRIB/deterministic-build/electrum-locale/locale/" "$LOCALE/"
    if ([ "$OMIT_UNCLEAN_FILES" != 1 ]); then
        "$CONTRIB/build_locale.sh" "$LOCALE" "$LOCALE"
    fi
)

if ([ "$OMIT_UNCLEAN_FILES" = 1 ]); then
    # FIXME side-effecting repo... though in practice, this script probably runs in fresh_clone
    rm -f "$PROJECT_ROOT/electrum/paymentrequest_pb2.py"
fi

(
    cd "$PROJECT_ROOT"

    find -exec touch -h -d '2000-11-11T11:11:11+00:00' {} +

    # note: .zip sdists would not be reproducible due to https://bugs.python.org/issue40963
    if ([ "$OMIT_UNCLEAN_FILES" = 1 ]); then
        PY_DISTDIR="dist/_sourceonly" # The DISTDIR variable of this script is only used to find where the output is *finally* placed.
    else
        PY_DISTDIR="dist"
    fi
    TZ=UTC faketime -f '2000-11-11 11:11:11' python3 setup.py --quiet sdist --format=gztar --dist-dir="$PY_DISTDIR"
    if ([ "$OMIT_UNCLEAN_FILES" = 1 ]); then
        python3 <<EOF
import importlib.util
import os

# load version.py; needlessly complicated alternative to "imp.load_source":
version_spec = importlib.util.spec_from_file_location('version', 'electrum/version.py')
version_module = importlib.util.module_from_spec(version_spec)
version_spec.loader.exec_module(version_module)

VER = version_module.ELECTRUM_VERSION
os.rename(f"dist/_sourceonly/Electrum-{VER}.tar.gz", f"dist/Electrum-sourceonly-{VER}.tar.gz")
EOF
        rmdir "$PY_DISTDIR"
    fi
)


info "done."
ls -la "$DISTDIR"
sha256sum "$DISTDIR"/*
