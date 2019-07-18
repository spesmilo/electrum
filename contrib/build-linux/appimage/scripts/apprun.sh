#!/bin/sh

set -e

APPDIR="$(dirname "$(readlink -e "$0")")"
. "$APPDIR"/common.conf

exec "$PYTHON" -s "${APPDIR}/usr/bin/electron-cash" "$@"
