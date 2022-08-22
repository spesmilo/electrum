#!/bin/bash

set -e

if [[ ! -d "$1" || -z "$2" ]]; then
    echo "usage: $0 locale_source_dir locale_dest_dir"
    echo "       The dirs can match, to build in place."
    exit 1
fi

if ! which msgfmt > /dev/null 2>&1; then
    echo "Please install gettext"
    exit 1
fi

cd "$1"
mkdir -p "$2"

for i in *; do
    dir="$2/$i/LC_MESSAGES"
    mkdir -p "$dir"
    (msgfmt --output-file="$dir/electrum.mo" "$i/electrum.po" || true)
done
