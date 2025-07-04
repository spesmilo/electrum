#!/bin/bash

# script to clone and build https://github.com/markusfisch/BarcodeScannerView and its dependencies,
# https://github.com/markusfisch/CameraView/ and https://github.com/markusfisch/zxing-cpp
# which are being used as barcode scanner in the Android app.

# To bump the version of BarcodeScannerView, get the newest version tag from the github repo,
# then get the required dependencies from
# https://github.com/markusfisch/BarcodeScannerView/blob/**VERSION_TAG**/barcodescannerview/build.gradle
# then update the commit hashes below. Also update kotlin-stdlib in buildozer_qml.spec to the
# "kotlin-version" specified in the used zxing-cpp commit:
# https://github.com/markusfisch/zxing-cpp/blob/master/wrappers/aar/build.gradle


BARCODE_SCANNER_VIEW_COMMIT_HASH="a4928bf83c0aae8ecb80e665d93f10b70232455b"  # 1.6.3
BARCODE_SCANNER_VIEW_REPO="https://github.com/markusfisch/BarcodeScannerView.git"

CAMERA_VIEW_COMMIT_HASH="745597d05bc6abfdb3637a09a8ecaf30fdce7b6e"  # 1.10.0
CAMERA_VIEW_REPO="https://github.com/markusfisch/CameraView.git"

ZXING_CPP_COMMIT_HASH="0741a597409ff69a96a326f3a65fe6440d87ad99"  # v2.2.0.5 using kotlin-stdlib 1.8.22
ZXING_CPP_REPO="https://github.com/markusfisch/zxing-cpp.git"


########################################################################################################
set -e

CONTRIB_ANDROID="$(dirname "$(readlink -e "$0")")"
CONTRIB="$CONTRIB_ANDROID"/..
CACHEDIR="$CONTRIB_ANDROID/.cache"
BUILDDIR="$CACHEDIR/builds"

. "$CONTRIB"/build_tools_util.sh

# target architecture passed as argument by`make_apk.sh`
TARGET_ARCH="$1"

# check if TARGET_ARCH is set and supported
if [[ "$TARGET_ARCH" != "armeabi-v7a" \
        && "$TARGET_ARCH" != "arm64-v8a" \
        && "$TARGET_ARCH" != "x86_64" ]]; then
    fail "make_barcode_scanner.sh invalid target architecture argument: $TARGET_ARCH"
fi

info "Building BarcodeScannerView and deps for architecture: $TARGET_ARCH"

# check if directories exist, create them if not
if [ ! -d "$CACHEDIR/aars" ]; then
    mkdir -p "$CACHEDIR/aars"
fi

if [ ! -d "$BUILDDIR" ]; then
    mkdir -p "$BUILDDIR"
fi


####### zxing-cpp ########

# check if zxing-cpp aar is already in cachedir, else build it
ZXING_CPP_BUILD_ID="$TARGET_ARCH-$ZXING_CPP_COMMIT_HASH"
if [ -f "$CACHEDIR/aars/zxing-cpp-$ZXING_CPP_BUILD_ID.aar" ]; then
    info "zxing-cpp for $ZXING_CPP_BUILD_ID already exists in cache, skipping build."
    cp "$CACHEDIR/aars/zxing-cpp-$ZXING_CPP_BUILD_ID.aar" "$CACHEDIR/aars/zxing-cpp.aar"
else
    info "Building zxing-cpp for $ZXING_CPP_BUILD_ID..."
    ZXING_CPP_DIR="$BUILDDIR/zxing-cpp"
    clone_or_update_repo "$ZXING_CPP_REPO" "$ZXING_CPP_COMMIT_HASH" "$ZXING_CPP_DIR"
    cd "$ZXING_CPP_DIR/wrappers/aar"
    chmod +x gradlew

    # Set local.properties to use SDK of docker container
    echo "sdk.dir=${ANDROID_SDK_HOME}" > local.properties
    # gradlew will install a specific NDK version required by zxing-cpp
    ./gradlew :zxingcpp:assembleRelease -Pandroid.injected.build.abi="$TARGET_ARCH"

    # Copy the built AAR to cache directory
    ZXING_AAR_SOURCE="$ZXING_CPP_DIR/wrappers/aar/zxingcpp/build/outputs/aar/zxingcpp-release.aar"
    ZXING_AAR_DEST_GENERIC="$CACHEDIR/aars/zxing-cpp.aar"
    ZXING_AAR_DEST_SPECIFIC="$CACHEDIR/aars/zxing-cpp-$ZXING_CPP_BUILD_ID.aar"
    if [ ! -f "$ZXING_AAR_SOURCE" ]; then
        fail "zxing-cpp AAR not found at $ZXING_AAR_SOURCE, build failed?"
    fi
    cp "$ZXING_AAR_SOURCE" "$ZXING_AAR_DEST_GENERIC"
    # keeping an arch specific copy allows to skip the build later if it already exists
    cp "$ZXING_AAR_SOURCE" "$ZXING_AAR_DEST_SPECIFIC"
    info "zxing-cpp AAR copied to $ZXING_AAR_DEST_GENERIC"
fi

########### CameraView ###########

CAMERA_VIEW_BUILD_ID="$CAMERA_VIEW_COMMIT_HASH"
if [ -f "$CACHEDIR/aars/CameraView-$CAMERA_VIEW_BUILD_ID.aar" ]; then
    info "CameraView AAR already exists in cache, skipping build."
    cp "$CACHEDIR/aars/CameraView-$CAMERA_VIEW_BUILD_ID.aar" "$CACHEDIR/aars/CameraView.aar"
else
    info "Building CameraView..."
    CAMERA_VIEW_DIR="$BUILDDIR/CameraView"
    clone_or_update_repo "$CAMERA_VIEW_REPO" "$CAMERA_VIEW_COMMIT_HASH" "$CAMERA_VIEW_DIR"
    cd "$CAMERA_VIEW_DIR"
    chmod +x gradlew

    echo "sdk.dir=${ANDROID_SDK_HOME}" > local.properties
    ./gradlew :cameraview:assembleRelease

    CAMERA_AAR_SOURCE="$CAMERA_VIEW_DIR/cameraview/build/outputs/aar/cameraview-release.aar"
    CAMERA_AAR_DEST_GENERIC="$CACHEDIR/aars/CameraView.aar"
    CAMERA_AAR_DEST_SPECIFIC="$CACHEDIR/aars/CameraView-$CAMERA_VIEW_BUILD_ID.aar"
    if [ ! -f "$CAMERA_AAR_SOURCE" ]; then
        fail "CameraView AAR not found at $CAMERA_AAR_SOURCE"
    fi
    cp "$CAMERA_AAR_SOURCE" "$CAMERA_AAR_DEST_GENERIC"
    cp "$CAMERA_AAR_SOURCE" "$CAMERA_AAR_DEST_SPECIFIC"
    info "CameraView AAR copied to $CAMERA_AAR_DEST"
fi

########### BarcodeScannerView ###########

BARCODE_SCANNER_VIEW_BUILD_ID="$BARCODE_SCANNER_VIEW_COMMIT_HASH"
if [ -f "$CACHEDIR/aars/BarcodeScannerView-$BARCODE_SCANNER_VIEW_BUILD_ID.aar" ]; then
    info "BarcodeScannerView AAR already exists in cache, skipping build."
    cp "$CACHEDIR/aars/BarcodeScannerView-$BARCODE_SCANNER_VIEW_BUILD_ID.aar" "$CACHEDIR/aars/BarcodeScannerView.aar"
else
    info "Building BarcodeScannerView..."
    BARCODE_SCANNER_VIEW_DIR="$BUILDDIR/BarcodeScannerView"
    clone_or_update_repo "$BARCODE_SCANNER_VIEW_REPO" "$BARCODE_SCANNER_VIEW_COMMIT_HASH" "$BARCODE_SCANNER_VIEW_DIR"
    cd "$BARCODE_SCANNER_VIEW_DIR"
    chmod +x gradlew

    echo "sdk.dir=${ANDROID_SDK_HOME}" > local.properties
    ./gradlew :barcodescannerview:assembleRelease

    BARCODE_AAR_SOURCE="$BARCODE_SCANNER_VIEW_DIR/barcodescannerview/build/outputs/aar/barcodescannerview-release.aar"
    BARCODE_AAR_DEST_GENERIC="$CACHEDIR/aars/BarcodeScannerView.aar"
    BARCODE_AAR_DEST_SPECIFIC="$CACHEDIR/aars/BarcodeScannerView-$BARCODE_SCANNER_VIEW_BUILD_ID.aar"
    if [ ! -f "$BARCODE_AAR_SOURCE" ]; then
        fail "BarcodeScannerView AAR not found at $BARCODE_AAR_SOURCE"
    fi
    cp "$BARCODE_AAR_SOURCE" "$BARCODE_AAR_DEST_GENERIC"
    cp "$BARCODE_AAR_SOURCE" "$BARCODE_AAR_DEST_SPECIFIC"
    info "BarcodeScannerView AAR copied to $BARCODE_AAR_DEST"
fi


info "All barcode scanner libraries built successfully for $TARGET_ARCH"
