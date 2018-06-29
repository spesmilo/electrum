#!/bin/bash

here=$(dirname "$0")
test -n "$here" -a -d "$here" || exit
cd $here


CERT_FILE=${CERT_FILE:-~/codesigning/cert.pem}
KEY_FILE=${KEY_FILE:-~/codesigning/key.pem}
if [[ ! -f "$CERT_FILE" ]]; then
    ls $CERT_FILE
    echo "Make sure that $CERT_FILE and $KEY_FILE exist"
fi

if ! which osslsigncode > /dev/null 2>&1; then
    echo "Please install osslsigncode"
fi

mkdir -p ./signed/dist >/dev/null 2>&1

echo "Found $(ls dist/*.exe | wc -w) files to sign."
for f in $(ls dist/*.exe); do
    echo "Checking GPG signatures for $f..."
    bad=0
    good=0
    for sig in $(ls $f.*.asc); do
        if gpg --verify $sig $f > /dev/null 2>&1; then
            (( good++ ))
        else
            (( bad++ ))
        fi
    done
    echo "$good good signature(s) for $f".
    if (( bad > 0 )); then
        echo "WARNING: $bad bad signature(s)"
        for sig in $(ls $f.*.asc); do
            gpg --verify $sig $f
            gpg --list-packets --verbose $sig
        done
        read -p "Do you want to continue (y/n)? " answer
        if [ "$answer" != "y" ]; then
            exit
        fi
    fi
    echo "Signing $f..."
    osslsigncode sign \
      -certs "$CERT_FILE" \
      -key "$KEY_FILE" \
      -n "Electrum" \
      -i "https://electrum.org/" \
      -t "http://timestamp.digicert.com/" \
      -in "$f" \
      -out "signed/$f"
    ls signed/$f -lah      
done
