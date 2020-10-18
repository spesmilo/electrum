#!/bin/sh

set -e

#RASTERIZE="clock1 clock2 clock3 clock4 clock5"
RASTERIZE=""
RESOLUTIONS="16 24 32 48 64"

require_command() {
    cmd="$1"
    msg="$2"
    if [ -z "$msg" ]; then
        msg="The '${cmd}' utility was not found. It is required by this script. Please install '${cmd}' using your package manager to proceed."
    fi
    if ! which $cmd > /dev/null 2>&1 ; then
        echo "$msg"
        exit 1
    fi
}

#require_command convert # Make sure user has imagemagick installed
require_command pyrcc5

for icon in $RASTERIZE ; do
    echo "Generating $icon.ico"

    for res in $RESOLUTIONS ; do
    	convert -background none -resize ${res}x$res icons/$icon.svg icons/${icon}_$res.png
    done

    ICON_PNGS=$(for res in $RESOLUTIONS ; do echo icons/${icon}_$res.png ; done)
    convert $ICON_PNGS icons/${icon}.ico
    rm $ICON_PNGS
done

echo "Generating icons.py"
pyrcc5 icons.qrc -o electroncash_gui/qt/icons.py
