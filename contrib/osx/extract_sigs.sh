#!/bin/sh
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# This script is based on https://github.com/bitcoin/bitcoin/blob/194b9b8792d9b0798fdb570b79fa51f1d1f5ebaf/contrib/macdeploy/detached-sig-create.sh

export LC_ALL=C
set -e

if [ $(uname) != "Darwin" ]; then
    echo "This script needs to be run on macOS."
    exit 1
fi

TEMPDIR="/tmp/electrum_compare_dmg/sigs.temp"
OUT=mac_extracted_sigs.tar.gz
OUTROOT=.

if [ -z "$1" ]; then
    echo "usage: $0 <path to .app>"
    exit 1
fi
BUNDLE="$1"
BUNDLE_BASENAME=$(basename "$BUNDLE")

rm -rf ${TEMPDIR}
mkdir -p ${TEMPDIR}

MAYBE_SIGNED_FILES=$(find "$BUNDLE/Contents/MacOS/" -type f)

echo "${MAYBE_SIGNED_FILES}" | while read i; do
    # skip files where pagestuff errors; these probably do not need signing:
    pagestuff "$i" -p 1>/dev/null 2>/dev/null || continue
    TARGETFILE="${BUNDLE_BASENAME}/$(echo "${i}" | sed "s|.*${BUNDLE}/||")"
    SIZE=$(pagestuff "$i" -p | tail -2 | grep size | sed 's/[^0-9]*//g')
    OFFSET=$(pagestuff "$i" -p | tail -2 | grep offset | sed 's/[^0-9]*//g')
    SIGNFILE="${TEMPDIR}/${OUTROOT}/${TARGETFILE}.sign"
    DIRNAME="$(dirname "${SIGNFILE}")"
    mkdir -p "${DIRNAME}"
    if [ -z ${QUIET} ]; then
        echo "Adding detached signature for: ${TARGETFILE}. Size: ${SIZE}. Offset: ${OFFSET}"
    fi
    dd if="$i" of="${SIGNFILE}" bs=1 skip=${OFFSET} count=${SIZE} 2>/dev/null
done

FILES_TO_COPY=$(cat << EOF
$BUNDLE/Contents/_CodeSignature/CodeResources
$BUNDLE/Contents/CodeResources
EOF
)

echo "${FILES_TO_COPY}" | while read i; do
    TARGETFILE="${BUNDLE_BASENAME}/$(echo "${i}" | sed "s|.*${BUNDLE}/||")"
    RESOURCE="${TEMPDIR}/${OUTROOT}/${TARGETFILE}"
    DIRNAME="$(dirname "${RESOURCE}")"
    mkdir -p "${DIRNAME}"
    if [ -z ${QUIET} ]; then
        echo "Adding resource for: \"${TARGETFILE}\""
    fi
    cp "${i}" "${RESOURCE}"
done

tar -C "${TEMPDIR}" -czf "${OUT}" .
rm -rf "${TEMPDIR}"
echo "Created ${OUT}"
