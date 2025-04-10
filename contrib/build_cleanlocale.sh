#!/bin/bash

set -e

CONTRIB="$(dirname "$(readlink -e "$0")")"
PROJECT_ROOT="$CONTRIB"/..

cd "$PROJECT_ROOT"
git submodule update --init

LOCALE="$PROJECT_ROOT/electrum/locale/"
cd "$LOCALE"
git clean -ffxd
git reset --hard
"$CONTRIB/build_locale.sh" "$LOCALE/locale" "$LOCALE/locale"
