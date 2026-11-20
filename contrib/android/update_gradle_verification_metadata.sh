#!/bin/bash
#
# Regenerates gradle-verification-metadata.xml, see gradle_verification_metadata.py.
# To be run after changing the gradle or android gradle plugin version of python-for-android.

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../.."
CONTRIB_ANDROID="$PROJECT_ROOT/contrib/android"
BUILD_UID=$(/usr/bin/stat -c %u "$PROJECT_ROOT")

docker build \
    --build-arg UID=$BUILD_UID \
    -t electrum-android-builder-img \
    --file "$CONTRIB_ANDROID/Dockerfile" \
    "$PROJECT_ROOT"

docker run --rm \
    -v "$PROJECT_ROOT":/home/user/wspace/electrum \
    --workdir /home/user/wspace/electrum \
    electrum-android-builder-img \
    ./contrib/android/gradle_verification_metadata.py
