#!/bin/bash

set -e

CONTRIB_ANDROID="$(dirname "$(readlink -e "$0")")"
CONTRIB="$CONTRIB_ANDROID"/..

cp "$CONTRIB/deterministic-build/requirements-build-android.txt" "$CONTRIB_ANDROID/requirements-build-android.txt"
sudo docker build -t electrum-android-builder-img "$CONTRIB_ANDROID"
rm "$CONTRIB_ANDROID/requirements-build-android.txt"
