#!/bin/bash
#
# env vars:
# - ELECBUILD_NOCACHE: if set, forces rebuild of docker image
# - ELECBUILD_COMMIT: if set, do a fresh clone and git checkout

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../../.."
PROJECT_ROOT_OR_FRESHCLONE_ROOT="$PROJECT_ROOT"
CONTRIB="$PROJECT_ROOT/contrib"
CONTRIB_APPIMAGE="$CONTRIB/build-linux/appimage"
DISTDIR="$PROJECT_ROOT/dist"
BUILD_UID=$(/usr/bin/stat -c %u "$PROJECT_ROOT")

# when bumping the runtime commit also check if the `type2-runtime-reproducible-build.patch` still works
TYPE2_RUNTIME_COMMIT="5e7217b7cfeecee1491c2d251e355c3cf8ba6e4d"
TYPE2_RUNTIME_REPO="https://github.com/AppImage/type2-runtime.git"

. "$CONTRIB"/build_tools_util.sh


DOCKER_BUILD_FLAGS=""
if [ ! -z "$ELECBUILD_NOCACHE" ] ; then
    info "ELECBUILD_NOCACHE is set. forcing rebuild of docker image."
    DOCKER_BUILD_FLAGS="--pull --no-cache"
fi

if [ -z "$ELECBUILD_COMMIT" ] ; then  # local dev build
    DOCKER_BUILD_FLAGS="$DOCKER_BUILD_FLAGS --build-arg UID=$BUILD_UID"
fi

info "building docker image."
docker build \
    $DOCKER_BUILD_FLAGS \
    -t electrum-appimage-builder-img \
    "$CONTRIB_APPIMAGE"

# maybe do fresh clone
if [ ! -z "$ELECBUILD_COMMIT" ] ; then
    info "ELECBUILD_COMMIT=$ELECBUILD_COMMIT. doing fresh clone and git checkout."
    FRESH_CLONE="/tmp/electrum_build/appimage/fresh_clone/electrum"
    rm -rf "$FRESH_CLONE" 2>/dev/null || ( info "we need sudo to rm prev FRESH_CLONE." && sudo rm -rf "$FRESH_CLONE" )
    umask 0022
    git clone "$PROJECT_ROOT" "$FRESH_CLONE"
    cd "$FRESH_CLONE"
    git checkout "$ELECBUILD_COMMIT"
    PROJECT_ROOT_OR_FRESHCLONE_ROOT="$FRESH_CLONE"
else
    info "not doing fresh clone."
fi

# build the type2-runtime binary, this build step uses a separate docker container 
# defined in the type2-runtime repo (patched with type2-runtime-reproducible-build.patch)
TYPE2_RUNTIME_REPO_DIR="$PROJECT_ROOT_OR_FRESHCLONE_ROOT/contrib/build-linux/appimage/.cache/appimage/type2-runtime"
(
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
) || fail "Failed to build type2-runtime"

info "building binary..."
# check uid and maybe chown. see #8261
if [ ! -z "$ELECBUILD_COMMIT" ] ; then  # fresh clone (reproducible build)
    if [ $(id -u) != "1000" ] || [ $(id -g) != "1000" ] ; then
        info "need to chown -R FRESH_CLONE dir. prompting for sudo."
        sudo chown -R 1000:1000 "$FRESH_CLONE"
    fi
fi
docker run -it \
    --name electrum-appimage-builder-cont \
    -v "$PROJECT_ROOT_OR_FRESHCLONE_ROOT":/opt/electrum \
    --rm \
    --workdir /opt/electrum/contrib/build-linux/appimage \
    electrum-appimage-builder-img \
    ./make_appimage.sh

# make sure resulting binary location is independent of fresh_clone
if [ ! -z "$ELECBUILD_COMMIT" ] ; then
    mkdir --parents "$DISTDIR/"
    cp -f "$FRESH_CLONE/dist"/* "$DISTDIR/"
fi
