#!/bin/bash

set -e

APPDIR="$(dirname "$(readlink -e "$0")")"

export LD_LIBRARY_PATH="${APPDIR}/usr/lib/:${APPDIR}/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH+:$LD_LIBRARY_PATH}"
export PATH="${APPDIR}/usr/bin:${PATH}"
export LDFLAGS="-L${APPDIR}/usr/lib/x86_64-linux-gnu -L${APPDIR}/usr/lib"

<<<<<<< HEAD
exec "${APPDIR}/usr/bin/python3.9" -s "${APPDIR}/usr/bin/electrodoge" "$@"
=======
exec "${APPDIR}/usr/bin/python3" -s "${APPDIR}/usr/bin/electrum" "$@"
>>>>>>> 4f574afe5af0f169a7d2799e62b6052b472fc8ad
