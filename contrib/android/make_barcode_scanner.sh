#!/bin/bash

# script to clone and build https://github.com/markusfisch/BarcodeScannerView and its dependencies,
# https://github.com/markusfisch/CameraView/ and https://github.com/markusfisch/zxing-cpp
# which are being used as barcode scanner in the Android app.

# To bump the version of BarcodeScannerView, get the newest version tag from the github repo,
# then get the required dependencies from
# https://github.com/markusfisch/BarcodeScannerView/blob/**VERSION_TAG**/barcodescannerview/build.gradle
# then update the commit hashes below. Also update kotlin-stdlib in buildozer_qml.spec: since
# zxing-cpp v3 there is no kotlin_version to copy, kotlin comes from AGP's built-in support,
# so read the version off the build with:
#   ./gradlew :zxingcpp:dependencies --configuration releaseRuntimeClasspath | grep kotlin-stdlib
#
# Upstream BarcodeScannerView resolves CameraView and zxing-cpp from jitpack.io. We patch that
# out (see patches/barcodescannerview-no-jitpack.patch) and serve the AARs we build ourselves,
# from a local maven repo, under the coordinates upstream asks for. So the *_VERSION values below
# must match the versions in the "dependencies" block of the BarcodeScannerView commit used:
# https://github.com/markusfisch/BarcodeScannerView/blob/**VERSION_TAG**/barcodescannerview/build.gradle


BARCODE_SCANNER_VIEW_COMMIT_HASH="0bdb69269c252bb6daef2f871b76403c8b051945"  # 1.6.5
BARCODE_SCANNER_VIEW_REPO="https://github.com/markusfisch/BarcodeScannerView.git"

CAMERA_VIEW_COMMIT_HASH="c806afadaf2ea81d454c9b81ef5938be1c9855cd"  # 1.10.2
CAMERA_VIEW_REPO="https://github.com/markusfisch/CameraView.git"
CAMERA_VIEW_VERSION="1.10.2"

ZXING_CPP_COMMIT_HASH="e88bb1d9e43502ad7073d29ee72cea4b758c1125"  # v3.1.0.0 using kotlin-stdlib 2.2.10
ZXING_CPP_REPO="https://github.com/markusfisch/zxing-cpp.git"
ZXING_CPP_VERSION="v3.1.0.0"

# maven groupId that BarcodeScannerView expects its deps under
MARKUSFISCH_GROUP_ID="com.github.markusfisch"

# don't let gradle pull in build dependencies
GRADLE_NO_SDK_DOWNLOAD="-Pandroid.builder.sdkDownload=false"

# set by make_verification_metadata.sh: regenerate the dependency verification metadata
# instead of enforcing it. gradle disables verification for such a run and rewrites
# gradle/verification-metadata.xml from what it actually resolves.
GRADLE_GEN_ARGS=()
if [ -n "$ELEC_WRITE_VERIFICATION_METADATA" ]; then
    GRADLE_GEN_ARGS=(--write-verification-metadata sha256)
fi

# CMake for the zxing-cpp native build.
ANDROID_CMAKE_VERSION="3.22.1"
ANDROID_CMAKE_HASH="9196644852a978012caf7a4067ba1898debf6cc204c3341562771e31080d6869"


########################################################################################################
set -e

CONTRIB_ANDROID="$(dirname "$(readlink -e "$0")")"
CONTRIB="$CONTRIB_ANDROID"/..
CACHEDIR="$CONTRIB_ANDROID/.cache"
BUILDDIR="$CACHEDIR/builds"
LOCAL_M2="$CACHEDIR/m2" # local maven repo, for local builds as deps
CMAKE_DIR="$CACHEDIR/cmake"   # pinned cmake for the zxing-cpp native build

. "$CONTRIB"/build_tools_util.sh

# publish an AAR we built ourselves into $LOCAL_M2, so gradle can resolve it as
# a regular maven module. usage: install_aar_to_local_m2 <aar> <group> <artifact> <version>
install_aar_to_local_m2() {
    local aar_path=$1
    local group_id=$2
    local artifact_id=$3
    local version=$4

    if [ ! -f "$aar_path" ]; then
        fail "install_aar_to_local_m2: AAR not found at $aar_path"
    fi

    local dest="$LOCAL_M2/${group_id//.//}/$artifact_id/$version"
    mkdir -p "$dest"
    cp "$aar_path" "$dest/$artifact_id-$version.aar"
    # minimal pom. note we deliberately declare no dependencies.
    cat > "$dest/$artifact_id-$version.pom" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>$group_id</groupId>
  <artifactId>$artifact_id</artifactId>
  <version>$version</version>
  <packaging>aar</packaging>
</project>
EOF
    info "installed $group_id:$artifact_id:$version into $LOCAL_M2"
}

# download the pinned CMake into $CMAKE_DIR, unless it is already there. kept under
# $CACHEDIR so it survives container restarts; the android sdk dir does not, as it lives
# in the image. the zxing-cpp build is pointed at it via cmake.dir in local.properties.
install_cmake() {
    if [ -x "$CMAKE_DIR/bin/cmake" ] && [ -x "$CMAKE_DIR/bin/ninja" ]; then
        info "cmake $ANDROID_CMAKE_VERSION already in cache, skipping download."
        return
    fi
    local archive="$CACHEDIR/cmake-$ANDROID_CMAKE_VERSION-linux.zip"
    local url="https://dl.google.com/android/repository/cmake-$ANDROID_CMAKE_VERSION-linux.zip"
    info "downloading cmake $ANDROID_CMAKE_VERSION..."
    rm -rf "$CMAKE_DIR" "$archive"
    curl --location --progress-bar "$url" --output "$archive" || fail "could not download $url"
    echo "$ANDROID_CMAKE_HASH  $archive" | sha256sum -c - || fail "sha256 mismatch for $archive"
    mkdir -p "$CMAKE_DIR"
    unzip -q "$archive" -d "$CMAKE_DIR" || fail "could not unpack $archive"
    rm -f "$archive"
    [ -x "$CMAKE_DIR/bin/cmake" ] || fail "no cmake binary at $CMAKE_DIR/bin/cmake"
    info "cmake $ANDROID_CMAKE_VERSION installed into $CMAKE_DIR"
}

# install the checked-in gradle dependency verification metadata into a checked out repo.
# with this in place gradle verifies the sha256 of every artifact it resolves (including the
# AGP plugin classpath) and fails the build on a mismatch, instead of trusting whatever the
# repositories hand back. usage: install_verification_metadata <name> <gradle-project-dir>
# regenerate after any toolchain or dependency bump with:
#   ./gradlew --write-verification-metadata sha256 <task>
# and copy the result back over verification-metadata/<name>.xml
install_verification_metadata() {
    local name=$1
    local project_dir=$2
    local src="$CONTRIB_ANDROID/verification-metadata/$name.xml"

    if [ -n "$ELEC_WRITE_VERIFICATION_METADATA" ]; then
        # about to be regenerated; installing a stale copy first would be pointless
        rm -f "$project_dir/gradle/verification-metadata.xml"
        return
    fi
    if [ ! -f "$src" ]; then
        fail "verification metadata not found at $src"
    fi
    mkdir -p "$project_dir/gradle"
    cp "$src" "$project_dir/gradle/verification-metadata.xml"
    info "installed dependency verification metadata for $name"
}

# in generation mode every gradle invocation must resolve against a cold artifact cache.
# gradle only records what it actually resolves, so artifacts already in modules-2 from an
# earlier project in the same run (parent poms, BOM descriptors like guava-parent and
# junit-bom) are silently left out, and the next clean build then fails verification on
# them. dropping modules-2 forces re-resolution; the wrapper dists are left alone so the
# gradle distribution itself is not re-downloaded each time.
drop_gradle_artifact_cache() {
    if [ -n "$ELEC_WRITE_VERIFICATION_METADATA" ]; then
        local home="${GRADLE_USER_HOME:-$HOME/.gradle}"
        info "generation mode: dropping $home/caches/modules-2"
        rm -rf "$home/caches/modules-2"
    fi
}

# check the given patch files exist, and set PATCH_ID to a short digest of them.
# PATCH_ID goes into the build cache keys, so editing a patch invalidates cached AARs.
set_patch_id() {
    local patch
    for patch in "$@"; do
        if [ ! -f "$patch" ]; then
            fail "patch not found at $patch"
        fi
    done
    PATCH_ID=$(cat "$@" "$CONTRIB_ANDROID"/verification-metadata/*.xml | sha256sum | cut -c1-12)
}

# target architecture passed as argument by`make_apk.sh`
TARGET_ARCH="$1"

# check if TARGET_ARCH is set and supported
if [[ "$TARGET_ARCH" != "armeabi-v7a" \
        && "$TARGET_ARCH" != "arm64-v8a" \
        && "$TARGET_ARCH" != "x86_64" ]]; then
    fail "make_barcode_scanner.sh invalid target architecture argument: $TARGET_ARCH"
fi

# set as ENV in contrib/android/Dockerfile, i.e. it names the build-tools that are actually
# installed in the builder image. we pass it into the gradle builds below, so that AGP uses
# those instead of downloading its own default version from Google mid-build.
if [ -z "$ANDROID_SDK_BUILD_TOOLS_VERSION" ]; then
    fail "ANDROID_SDK_BUILD_TOOLS_VERSION is not set (expected from the builder image)"
fi

# same idea for the NDK, but AGP wants the numeric revision (e.g. 28.2.13676358) while the
# Dockerfile pins the release name (e.g. 28c), so read it back off the NDK we actually have.
# the zxing-cpp toolchain patch sets both ndkPath and ndkVersion: AGP defaults ndkVersion to
# its own bundled version and fails if the two disagree.
if [ -z "$ANDROID_NDK_HOME" ] || [ ! -f "$ANDROID_NDK_HOME/source.properties" ]; then
    fail "ANDROID_NDK_HOME is not set or does not look like an NDK (expected from the builder image)"
fi
export ELEC_NDK_VERSION=$(grep '^Pkg.Revision' "$ANDROID_NDK_HOME/source.properties" | cut -d= -f2 | tr -d ' ')
if [ -z "$ELEC_NDK_VERSION" ]; then
    fail "could not read Pkg.Revision from $ANDROID_NDK_HOME/source.properties"
fi

info "Building BarcodeScannerView and deps for architecture: $TARGET_ARCH"
info "using build-tools $ANDROID_SDK_BUILD_TOOLS_VERSION and NDK $ELEC_NDK_VERSION from the builder image"

# check if directories exist, create them if not
if [ ! -d "$CACHEDIR/aars" ]; then
    mkdir -p "$CACHEDIR/aars"
fi

if [ ! -d "$BUILDDIR" ]; then
    mkdir -p "$BUILDDIR"
fi


####### zxing-cpp ########

ZXING_CPP_PATCHES=(
    "$CONTRIB_ANDROID/patches/zxingcpp-toolchain-from-image.patch"
    "$CONTRIB_ANDROID/patches/zxingcpp-no-zint.patch"
)
set_patch_id "${ZXING_CPP_PATCHES[@]}"

# check if zxing-cpp aar is already in cachedir, else build it
ZXING_CPP_BUILD_ID="$TARGET_ARCH-$ZXING_CPP_COMMIT_HASH-$PATCH_ID"
if [ -f "$CACHEDIR/aars/zxing-cpp-$ZXING_CPP_BUILD_ID.aar" ]; then
    info "zxing-cpp for $ZXING_CPP_BUILD_ID already exists in cache, skipping build."
    cp "$CACHEDIR/aars/zxing-cpp-$ZXING_CPP_BUILD_ID.aar" "$CACHEDIR/aars/zxing-cpp.aar"
else
    info "Building zxing-cpp for $ZXING_CPP_BUILD_ID..."
    ZXING_CPP_DIR="$BUILDDIR/zxing-cpp"
    clone_or_update_repo "$ZXING_CPP_REPO" "$ZXING_CPP_COMMIT_HASH" "$ZXING_CPP_DIR"
    # use the toolchain from the builder image, and drop the libzint writer
    for patch in "${ZXING_CPP_PATCHES[@]}"; do
        apply_patch "$patch" "$ZXING_CPP_DIR"
    done
    cd "$ZXING_CPP_DIR/wrappers/aar"
    chmod +x gradlew

    install_cmake
    install_verification_metadata zxingcpp "$ZXING_CPP_DIR/wrappers/aar"

    # Set local.properties to use SDK of docker container, and our pinned cmake
    echo "sdk.dir=${ANDROID_SDK_HOME}" > local.properties
    echo "cmake.dir=${CMAKE_DIR}" >> local.properties
    drop_gradle_artifact_cache
    ./gradlew :zxingcpp:assembleRelease "$GRADLE_NO_SDK_DOWNLOAD" "${GRADLE_GEN_ARGS[@]}" \
        -Pandroid.injected.build.abi="$TARGET_ARCH"

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

CAMERA_VIEW_PATCHES=(
    "$CONTRIB_ANDROID/patches/cameraview-toolchain-from-image.patch"
)
set_patch_id "${CAMERA_VIEW_PATCHES[@]}"

CAMERA_VIEW_BUILD_ID="$CAMERA_VIEW_COMMIT_HASH-$PATCH_ID"
if [ -f "$CACHEDIR/aars/CameraView-$CAMERA_VIEW_BUILD_ID.aar" ]; then
    info "CameraView AAR already exists in cache, skipping build."
    cp "$CACHEDIR/aars/CameraView-$CAMERA_VIEW_BUILD_ID.aar" "$CACHEDIR/aars/CameraView.aar"
else
    info "Building CameraView..."
    CAMERA_VIEW_DIR="$BUILDDIR/CameraView"
    clone_or_update_repo "$CAMERA_VIEW_REPO" "$CAMERA_VIEW_COMMIT_HASH" "$CAMERA_VIEW_DIR"
    # use the toolchain from the builder image
    for patch in "${CAMERA_VIEW_PATCHES[@]}"; do
        apply_patch "$patch" "$CAMERA_VIEW_DIR"
    done
    install_verification_metadata cameraview "$CAMERA_VIEW_DIR"

    cd "$CAMERA_VIEW_DIR"
    chmod +x gradlew

    echo "sdk.dir=${ANDROID_SDK_HOME}" > local.properties
    drop_gradle_artifact_cache
    ./gradlew :cameraview:assembleRelease "$GRADLE_NO_SDK_DOWNLOAD" "${GRADLE_GEN_ARGS[@]}"

    CAMERA_AAR_SOURCE="$CAMERA_VIEW_DIR/cameraview/build/outputs/aar/cameraview-release.aar"
    CAMERA_AAR_DEST_GENERIC="$CACHEDIR/aars/CameraView.aar"
    CAMERA_AAR_DEST_SPECIFIC="$CACHEDIR/aars/CameraView-$CAMERA_VIEW_BUILD_ID.aar"
    if [ ! -f "$CAMERA_AAR_SOURCE" ]; then
        fail "CameraView AAR not found at $CAMERA_AAR_SOURCE"
    fi
    cp "$CAMERA_AAR_SOURCE" "$CAMERA_AAR_DEST_GENERIC"
    cp "$CAMERA_AAR_SOURCE" "$CAMERA_AAR_DEST_SPECIFIC"
    info "CameraView AAR copied to $CAMERA_AAR_DEST_GENERIC"
fi

########### BarcodeScannerView ###########

BARCODE_SCANNER_VIEW_PATCHES=(
    "$CONTRIB_ANDROID/patches/barcodescannerview-no-jitpack.patch"
    "$CONTRIB_ANDROID/patches/barcodescannerview-toolchain-from-image.patch"
    "$CONTRIB_ANDROID/patches/barcodescannerview-zxingcpp-v3.patch"
)
set_patch_id "${BARCODE_SCANNER_VIEW_PATCHES[@]}"

BARCODE_SCANNER_VIEW_BUILD_ID="$BARCODE_SCANNER_VIEW_COMMIT_HASH-$PATCH_ID"
if [ -f "$CACHEDIR/aars/BarcodeScannerView-$BARCODE_SCANNER_VIEW_BUILD_ID.aar" ]; then
    info "BarcodeScannerView AAR already exists in cache, skipping build."
    cp "$CACHEDIR/aars/BarcodeScannerView-$BARCODE_SCANNER_VIEW_BUILD_ID.aar" "$CACHEDIR/aars/BarcodeScannerView.aar"
else
    info "Building BarcodeScannerView..."
    BARCODE_SCANNER_VIEW_DIR="$BUILDDIR/BarcodeScannerView"
    clone_or_update_repo "$BARCODE_SCANNER_VIEW_REPO" "$BARCODE_SCANNER_VIEW_COMMIT_HASH" "$BARCODE_SCANNER_VIEW_DIR"
    # note clone_or_update_repo resets the worktree, so these always apply to a clean tree.
    for patch in "${BARCODE_SCANNER_VIEW_PATCHES[@]}"; do
        apply_patch "$patch" "$BARCODE_SCANNER_VIEW_DIR"
    done
    rm -rf "$LOCAL_M2"
    install_aar_to_local_m2 "$CACHEDIR/aars/CameraView.aar" \
        "$MARKUSFISCH_GROUP_ID" "CameraView" "$CAMERA_VIEW_VERSION"
    install_aar_to_local_m2 "$CACHEDIR/aars/zxing-cpp.aar" \
        "$MARKUSFISCH_GROUP_ID" "zxing-cpp" "$ZXING_CPP_VERSION"
    export ELEC_LOCAL_M2="$LOCAL_M2"

    install_verification_metadata barcodescannerview "$BARCODE_SCANNER_VIEW_DIR"

    cd "$BARCODE_SCANNER_VIEW_DIR"
    chmod +x gradlew

    echo "sdk.dir=${ANDROID_SDK_HOME}" > local.properties
    drop_gradle_artifact_cache
    ./gradlew :barcodescannerview:assembleRelease "$GRADLE_NO_SDK_DOWNLOAD" "${GRADLE_GEN_ARGS[@]}"

    BARCODE_AAR_SOURCE="$BARCODE_SCANNER_VIEW_DIR/barcodescannerview/build/outputs/aar/barcodescannerview-release.aar"
    BARCODE_AAR_DEST_GENERIC="$CACHEDIR/aars/BarcodeScannerView.aar"
    BARCODE_AAR_DEST_SPECIFIC="$CACHEDIR/aars/BarcodeScannerView-$BARCODE_SCANNER_VIEW_BUILD_ID.aar"
    if [ ! -f "$BARCODE_AAR_SOURCE" ]; then
        fail "BarcodeScannerView AAR not found at $BARCODE_AAR_SOURCE"
    fi
    cp "$BARCODE_AAR_SOURCE" "$BARCODE_AAR_DEST_GENERIC"
    cp "$BARCODE_AAR_SOURCE" "$BARCODE_AAR_DEST_SPECIFIC"
    info "BarcodeScannerView AAR copied to $BARCODE_AAR_DEST_GENERIC"
fi


info "All barcode scanner libraries built successfully for $TARGET_ARCH"
