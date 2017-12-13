#!/bin/bash
# Lucky number
export PYTHONHASHSEED=22

if [ ! -z "$1" ]; then
    to_build="$1"
fi

here=$(dirname "$0")

echo "Clearing $here/build and $here/dist..."
rm $here/build/* -rf
rm $here/dist/* -rf

$here/prepare-wine.sh && \
$here/prepare-pyinstaller.sh && \
$here/prepare-hw.sh || exit 1

echo "Resetting modification time in C:\Python..."
# (Because of some bugs in pyinstaller)
pushd /opt/wine64/drive_c/python*
find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd
ls -l /opt/wine64/drive_c/python*

$here/build-electrum-git.sh $to_build && \
echo "Done."
