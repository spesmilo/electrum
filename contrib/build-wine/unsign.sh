#!/bin/bash
here=$(dirname "$0")
test -n "$here" -a -d "$here" || exit
cd $here

if ! which osslsigncode > /dev/null 2>&1; then
    echo "Please install osslsigncode"
    exit
fi

# exit if command fails
set -e

mkdir -p signed >/dev/null 2>&1
mkdir -p signed/stripped >/dev/null 2>&1

version=`python3 -c "import electrum; print(electrum.version.ELECTRUM_VERSION)"`

echo "Found $(ls dist/*.exe | wc -w) files to verify."

for mine in $(ls dist/*.exe); do
    echo "---------------"
    f=$(basename $mine)
    if test -f signed/$f; then
        echo "Found file at signed/$f"
    else
        echo "Downloading https://download.electrum.org/$version/$f"
        wget -q https://download.electrum.org/$version/$f -O signed/$f
    fi
    out="signed/stripped/$f"
    # Remove PE signature from signed binary
    osslsigncode remove-signature -in signed/$f -out $out > /dev/null 2>&1
    chmod +x $out
    if cmp -s $out $mine; then
        echo "Success: $f"
        #gpg --sign --armor --detach signed/$f
    else
        echo "Failure: $f"
        exit 1
    fi
done

exit 0
