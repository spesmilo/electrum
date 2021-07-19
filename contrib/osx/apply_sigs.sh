#!/bin/sh
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# This script is based on https://github.com/bitcoin/bitcoin/blob/194b9b8792d9b0798fdb570b79fa51f1d1f5ebaf/contrib/macdeploy/detached-sig-apply.sh

export LC_ALL=C
set -e

if [ $(uname) != "Darwin" ]; then
    echo "This script needs to be run on macOS."
    exit 1
fi

CP=gcp

UNSIGNED="$1"
SIGNATURE="$2"
ARCH=x86_64
OUTDIR="/tmp/electrum_compare_dmg/signed_app"

if [ -z "$UNSIGNED" ]; then
    echo "usage: $0 <unsigned app> <path to mac_extracted_sigs.tar.gz>"
    exit 1
fi

if [ -z "$SIGNATURE" ]; then
    echo "usage: $0 <unsigned app> <path to mac_extracted_sigs.tar.gz>"
    exit 1
fi

rm -rf ${OUTDIR} && mkdir -p ${OUTDIR}
${CP} -rf ${UNSIGNED} ${OUTDIR}
tar xf "${SIGNATURE}" -C ${OUTDIR}

find ${OUTDIR} -name "*.sign" | while read i; do
    SIZE=$(gstat -c %s "${i}")
    TARGET_FILE="$(echo "${i}" | sed 's/\.sign$//')"

    if [ -z ${QUIET} ]; then
        echo "Allocating space for the signature of size ${SIZE} in ${TARGET_FILE}"
    fi
    codesign_allocate -i "${TARGET_FILE}" -a ${ARCH} ${SIZE} -o "${i}.tmp"

    OFFSET=$(pagestuff "${i}.tmp" -p | tail -2 | grep offset | sed 's/[^0-9]*//g')
    if [ -z ${QUIET} ]; then
        echo "Attaching signature at offset ${OFFSET}"
    fi

    dd if="$i" of="${i}.tmp" bs=1 seek=${OFFSET} count=${SIZE} 2>/dev/null
    mv "${i}.tmp" "${TARGET_FILE}"
    rm "${i}"
    if [ -z ${QUIET} ]; then
        echo "Success."
    fi
done
echo "Done. .app with sigs applied is at: ${OUTDIR}"
