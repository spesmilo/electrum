#!/bin/bash

set -e

if [[ ! -d "$1" || -z "$2" ]]; then
    echo "usage: $0 locale_source_dir locale_dest_dir"
    echo "       The dirs can match, to build in place."
    exit 1
fi

# convert $1 and $2 to abs paths
SRC_DIR="$(realpath "$1" 2> /dev/null || grealpath "$1")"
DST_DIR="$(realpath "$2" 2> /dev/null || grealpath "$2")"

if ! which msgfmt > /dev/null 2>&1; then
    echo "Please install gettext"
    exit 1
fi

cd "$SRC_DIR"
mkdir -p "$DST_DIR"

for i in *; do
    dir="$DST_DIR/$i/LC_MESSAGES"
    mkdir -p "$dir"
    (msgfmt --output-file="$dir/electrum.mo" "$i/electrum.po" || true)
done
