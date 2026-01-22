#!/bin/bash

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../../.."
CONTRIB="$PROJECT_ROOT/contrib"
CONTRIB_APPIMAGE="$CONTRIB/build-linux/appimage"

# when bumping the runtime commit also check if the `type2-runtime-reproducible-build.patch` still works
TYPE2_RUNTIME_COMMIT="5e7217b7cfeecee1491c2d251e355c3cf8ba6e4d"
TYPE2_RUNTIME_REPO="https://github.com/AppImage/type2-runtime.git"

. "$CONTRIB"/build_tools_util.sh


TYPE2_RUNTIME_REPO_DIR="$PROJECT_ROOT/contrib/build-linux/appimage/.cache/appimage/type2-runtime"
if [ -f "$TYPE2_RUNTIME_REPO_DIR/runtime-x86_64" ]; then
    info "type2-runtime already built, skipping"
    exit 0
fi
clone_or_update_repo "$TYPE2_RUNTIME_REPO" "$TYPE2_RUNTIME_COMMIT" "$TYPE2_RUNTIME_REPO_DIR"

# Apply patch to make runtime build reproducible
info "Applying type2-runtime patch..."
cd "$TYPE2_RUNTIME_REPO_DIR"
git apply "$CONTRIB_APPIMAGE/patches/type2-runtime-reproducible-build.patch" || fail "Failed to apply runtime repo patch"

info "building type2-runtime in build container..."
cd "$TYPE2_RUNTIME_REPO_DIR/scripts/docker"
env ARCH=x86_64 ./build-with-docker.sh
mv "./runtime-x86_64" "$TYPE2_RUNTIME_REPO_DIR/"

# clean up the empty created 'out' dir to prevent permission issues
rm -rf "$TYPE2_RUNTIME_REPO_DIR/out"

info "runtime build successful: $(sha256sum "$TYPE2_RUNTIME_REPO_DIR/runtime-x86_64")"
