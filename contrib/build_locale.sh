#!/bin/bash

if [ ! -d "$1" ]; then
    echo "usage: $0 path/to/locale"
    exit 1
fi

if ! which msgfmt > /dev/null 2>&1; then
    echo "Please install gettext"
    exit 1
fi

for i in "$1/"*; do
  mkdir -p "$i/LC_MESSAGES"
  (msgfmt --output-file="$i/LC_MESSAGES/electrum.mo" "$i/electrum.po" || true)
done
