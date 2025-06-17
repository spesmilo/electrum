#!/bin/bash

set -e

CONTRIB_LOCALE="$(dirname "$(realpath "$0" 2> /dev/null || grealpath "$0")")"
CONTRIB="$CONTRIB_LOCALE"/..
PROJECT_ROOT="$CONTRIB"/..

cd "$PROJECT_ROOT"
git submodule update --init

LOCALE="$PROJECT_ROOT/electrum/locale/"
cd "$LOCALE"
git clean -ffxd
git reset --hard
"$CONTRIB_LOCALE/build_locale.sh" "$LOCALE/locale" "$LOCALE/locale"
