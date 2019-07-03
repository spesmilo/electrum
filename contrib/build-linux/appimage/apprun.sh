#!/bin/bash

set -e

APPDIR="$(dirname "$(readlink -e "$0")")"
PYTHON="${APPDIR}/usr/bin/python3.6"

export LD_LIBRARY_PATH="${APPDIR}/usr/lib/:${APPDIR}/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH+:$LD_LIBRARY_PATH}"
export PATH="${APPDIR}/usr/bin:${PATH}"
export LDFLAGS="-L${APPDIR}/usr/lib/x86_64-linux-gnu -L${APPDIR}/usr/lib"

if ! "$PYTHON" -s "${APPDIR}/test-freetype.py" ; then
    export LD_LIBRARY_PATH="${APPDIR}/usr/lib/fonts${LD_LIBRARY_PATH+:$LD_LIBRARY_PATH}"
fi

exec "$PYTHON" -s "${APPDIR}/usr/bin/electron-cash" "$@"
