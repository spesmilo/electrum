#!/bin/bash

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../../.."
CONTRIB="$PROJECT_ROOT/contrib"
CONTRIB_SDIST="$CONTRIB/build-linux/sdist"
DISTDIR="$PROJECT_ROOT/dist"

. "$CONTRIB"/build_tools_util.sh


"$CONTRIB"/make_packages || fail "make_packages failed"

"$CONTRIB_SDIST"/make_tgz || fail "make_tgz failed"


info "done."
ls -la "$DISTDIR"
sha256sum "$DISTDIR"/*
