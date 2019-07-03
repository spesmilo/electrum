#!/usr/bin/env bash

. $(dirname "$0")/../build_tools_util.sh


function DoCodeSignMaybe { # ARGS: infoName fileOrDirName codesignIdentity
    infoName="$1"
    file="$2"
    identity="$3"
    deep=""
    if [ -z "$identity" ]; then
        # we are ok with them not passing anything; master script calls us unconditionally even if no identity is specified
        return
    fi
    if [ -d "$file" ]; then
        deep="--deep"
    fi
    if [ -z "$infoName" ] || [ -z "$file" ] || [ -z "$identity" ] || [ ! -e "$file" ]; then
        fail "Argument error to internal function DoCodeSignMaybe()"
    fi
    info "Code signing ${infoName}..."
    codesign -f -v $deep -s "$identity" "$file" || fail "Could not code sign ${infoName}"
}

function realpath() {
    [[ $1 = /* ]] && echo "$1" || echo "$PWD/${1#./}"
}
