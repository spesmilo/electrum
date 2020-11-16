#!/usr/bin/env bash

. $(dirname "$0")/../build_tools_util.sh


function DoCodeSignMaybe { # ARGS: infoName fileOrDirName
    infoName="$1"
    file="$2"
    deep=""
    if [ -z "$CODESIGN_CERT" ]; then
        # no cert -> we won't codesign
        return
    fi
    if [ -d "$file" ]; then
        deep="--deep"
    fi
    if [ -z "$infoName" ] || [ -z "$file" ] || [ ! -e "$file" ]; then
        fail "Argument error to internal function DoCodeSignMaybe()"
    fi
    hardened_arg="--entitlements=${CONTRIB_OSX}/entitlements.plist -o runtime"

    info "Code signing ${infoName}..."
    codesign -f -v $deep -s "$CODESIGN_CERT" $hardened_arg "$file" || fail "Could not code sign ${infoName}"
}

function realpath() {
    [[ $1 = /* ]] && echo "$1" || echo "$PWD/${1#./}"
}
