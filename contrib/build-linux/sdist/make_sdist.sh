#!/bin/bash

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../../.."
CONTRIB="$PROJECT_ROOT/contrib"
CONTRIB_SDIST="$CONTRIB/build-linux/sdist"
DISTDIR="$PROJECT_ROOT/dist"
BUILDDIR="$CONTRIB_SDIST/build"

. "$CONTRIB"/build_tools_util.sh

git -C "$PROJECT_ROOT" rev-parse 2>/dev/null || fail "Building outside a git clone is not supported."

rm -rf "$BUILDDIR"
mkdir -p "$BUILDDIR" "$DISTDIR"

python3 --version || fail "python interpreter not found"

break_legacy_easy_install

rm -rf "$PROJECT_ROOT/packages/"
if ([ "$OMIT_UNCLEAN_FILES" != 1 ]); then
    "$CONTRIB"/make_packages.sh || fail "make_packages failed"
fi

info "preparing electrum-locale."
(
    "$CONTRIB/locale/build_cleanlocale.sh"
    # By default, include both source (.po) and compiled (.mo) locale files in the source dist.
    # Set option OMIT_UNCLEAN_FILES=1 to exclude the compiled locale files
    # see https://askubuntu.com/a/144139 (also see MANIFEST.in)
    if ([ "$OMIT_UNCLEAN_FILES" = 1 ]); then
        rm -r "$PROJECT_ROOT/electrum/locale/locale"/*/LC_MESSAGES/electrum.mo
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
        PY_DISTDIR="$BUILDDIR/dist1/_sourceonly" # The DISTDIR variable of this script is only used to find where the output is *finally* placed.
    else
        PY_DISTDIR="$BUILDDIR/dist1"
    fi
    # build initial tar.gz
    python3 setup.py --quiet sdist --format=gztar --dist-dir="$PY_DISTDIR"

    VERSION=$("$CONTRIB"/print_electrum_version.py)
    if ([ "$OMIT_UNCLEAN_FILES" = 1 ]); then
        FINAL_DISTNAME="Electrum-sourceonly-$VERSION.tar.gz"
    else
        FINAL_DISTNAME="Electrum-$VERSION.tar.gz"
    fi
    if ([ "$OMIT_UNCLEAN_FILES" = 1 ]); then
        mv "$PY_DISTDIR/Electrum-$VERSION.tar.gz" "$PY_DISTDIR/../$FINAL_DISTNAME"
        rmdir "$PY_DISTDIR"
    fi

    # the initial tar.gz is not reproducible, see https://github.com/pypa/setuptools/issues/2133
    # so we untar, fix timestamps, and then re-tar
    mkdir -p "$BUILDDIR/dist2"
    cd "$BUILDDIR/dist2"
    tar -xzf "$BUILDDIR/dist1/$FINAL_DISTNAME"
    find -exec touch -h -d '2000-11-11T11:11:11+00:00' {} +
    GZIP=-n tar --sort=name -czf "$FINAL_DISTNAME" "Electrum-$VERSION/"
    mv "$FINAL_DISTNAME" "$DISTDIR/$FINAL_DISTNAME"
)


info "done."
ls -la "$DISTDIR"
sha256sum "$DISTDIR"/*
