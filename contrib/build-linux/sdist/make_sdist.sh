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

if ([ "$OMIT_UNCLEAN_FILES" != 1 ]); then
  "$CONTRIB"/make_packages || fail "make_packages failed"
fi

git submodule update --init

(
    # By default, include both source (.po) and compiled (.mo) locale files in the source dist.
    # Set option OMIT_UNCLEAN_FILES=1 to exclude the compiled locale files
    # see https://askubuntu.com/a/144139 (also see MANIFEST.in)
    rm -rf "$LOCALE"
    cp -r "$CONTRIB/deterministic-build/electrum-locale/locale/" "$LOCALE/"
    if ([ "$OMIT_UNCLEAN_FILES" != 1 ]); then
      "$CONTRIB/build_locale.sh" "$LOCALE"
    fi
)

if ([ "$OMIT_UNCLEAN_FILES" = 1 ]); then
  rm "$PROJECT_ROOT/electrum/paymentrequest_pb2.py"
fi

(
    cd "$PROJECT_ROOT"

    find -exec touch -h -d '2000-11-11T11:11:11+00:00' {} +

    # note: .zip sdists would not be reproducible due to https://bugs.python.org/issue40963
    if ([ "$OMIT_UNCLEAN_FILES" = 1 ])
        then PY_DISTDIR="dist/_sourceonly" # The DISTDIR variable of this script is only used to find where the output is *finally* placed.
        else PY_DISTDIR="dist"
    fi
    TZ=UTC faketime -f '2000-11-11 11:11:11' python3 setup.py --quiet sdist --format=gztar --dist-dir="$PY_DISTDIR"
    if ([ "$OMIT_UNCLEAN_FILES" = 1 ]); then
        for fn in "$DISTDIR/_sourceonly/"*; do
            # Since ELECTRUM_VERSION is not available to us in this script, we have to use a regex.
            # Expression 1: Electrum-X.Y.Z.tar.gz -> Electrum-sourceonly-X.Y.Z.tar.gz
            #   Capture group \1 = Electrum
            #   Capture group \2 = X.Y.Z.tar.gz
            # Expression 2: dist/_sourceonly/X.tar.gz -> dist/X.tar.gz
            mv "$fn" $(sed \
                -e 's/\(.*\)-\([^-]*\)/\1-sourceonly-\2/' \
                -e 's/\/_sourceonly//' \
                <<< "$fn")
        done
        rmdir "$PY_DISTDIR"
    fi
)


info "done."
ls -la "$DISTDIR"
sha256sum "$DISTDIR"/*
