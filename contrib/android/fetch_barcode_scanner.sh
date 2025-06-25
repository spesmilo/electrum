#!/bin/bash

# script to fetch and pin https://github.com/markusfisch/BarcodeScannerView and its dependencies,
# https://github.com/markusfisch/CameraView/ and https://github.com/markusfisch/zxing-cpp
# which are being used as barcode scanner in the Android app.

# To bump the version of BarcodeScannerView, get the newest version tag from the github repo,
# then get the required dependencies from
# https://jitpack.io/com/github/markusfisch/BarcodeScannerView/**NEWEST_VERSION**/BarcodeScannerView-**NEWEST_VERSION**.pom
# then fetch the aars from jitpack and update the versions and sha256s below. Also update kotlin-stdlib
# in buildozer_qml.spec

BARCODE_SCANNER_VIEW_VERSION="1.6.0"
BARCODE_SCANNER_VIEW_AAR_SHA256="2be6c9a5ab86f7198683af4a6c0e5acd3e8fe6a02df2d12c3b716dc422537789"

CAMERA_VIEW_VERSION="1.9.2"
CAMERA_VIEW_AAR_SHA256="3c9be35d29b84637d2a2b0e0e7253bc5a35408fafb26c5cb7225aeb7326e2be4"

ZXING_CPP_VERSION="v2.2.0.1"
ZXING_CPP_AAR_SHA256="7991381f181ff16555c4ac9c5d83e6a0d3a7da896efb8c3807897305ca33b957"

DOWNLOAD_REPOSITORY_ROOT="https://jitpack.io/com/github/markusfisch"

set -e

CONTRIB_ANDROID="$(dirname "$(readlink -e "$0")")"
CONTRIB="$CONTRIB_ANDROID"/..
CACHEDIR="$CONTRIB_ANDROID/.cache"

. "$CONTRIB"/build_tools_util.sh

# check if $CACHEDIR/aars exists, create it if not
if [ ! -d "$CACHEDIR/aars" ]; then
    mkdir -p "$CACHEDIR/aars"
fi

info "Fetching BarcodeScannerView..."
download_if_not_exist "$CACHEDIR/aars/BarcodeScannerView.aar" \
    "${DOWNLOAD_REPOSITORY_ROOT}/BarcodeScannerView/${BARCODE_SCANNER_VIEW_VERSION}/BarcodeScannerView-${BARCODE_SCANNER_VIEW_VERSION}.aar"
verify_hash "$CACHEDIR/aars/BarcodeScannerView.aar" "$BARCODE_SCANNER_VIEW_AAR_SHA256"

info "Fetching CameraView..."
download_if_not_exist "$CACHEDIR/aars/CameraView.aar" \
    "${DOWNLOAD_REPOSITORY_ROOT}/CameraView/${CAMERA_VIEW_VERSION}/CameraView-${CAMERA_VIEW_VERSION}.aar"
verify_hash "$CACHEDIR/aars/CameraView.aar" "$CAMERA_VIEW_AAR_SHA256"

info "Fetching zxing-cpp..."
download_if_not_exist "$CACHEDIR/aars/zxing-cpp.aar" \
    "${DOWNLOAD_REPOSITORY_ROOT}/zxing-cpp/${ZXING_CPP_VERSION}/zxing-cpp-${ZXING_CPP_VERSION}.aar"
verify_hash "$CACHEDIR/aars/zxing-cpp.aar" "$ZXING_CPP_AAR_SHA256"
