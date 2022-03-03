#!/bin/bash
#
# env vars:
# - ELECBUILD_NOCACHE: if set, forces rebuild of docker image
# - ELECBUILD_COMMIT: if set, do a fresh clone and git checkout

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../.."
PROJECT_ROOT_OR_FRESHCLONE_ROOT="$PROJECT_ROOT"
CONTRIB="$PROJECT_ROOT/contrib"
CONTRIB_ANDROID="$CONTRIB/android"
DISTDIR="$PROJECT_ROOT/dist"

. "$CONTRIB"/build_tools_util.sh


DOCKER_BUILD_FLAGS=""
if [ ! -z "$ELECBUILD_NOCACHE" ] ; then
    info "ELECBUILD_NOCACHE is set. forcing rebuild of docker image."
    DOCKER_BUILD_FLAGS="--pull --no-cache"
fi

info "building docker image."
cp "$CONTRIB/deterministic-build/requirements-build-android.txt" "$CONTRIB_ANDROID/requirements-build-android.txt"
sudo docker build \
    $DOCKER_BUILD_FLAGS \
    -t electrum-android-builder-img \
    "$CONTRIB_ANDROID"
rm "$CONTRIB_ANDROID/requirements-build-android.txt"


# maybe do fresh clone
if [ ! -z "$ELECBUILD_COMMIT" ] ; then
    info "ELECBUILD_COMMIT=$ELECBUILD_COMMIT. doing fresh clone and git checkout."
    FRESH_CLONE="$CONTRIB_ANDROID/fresh_clone/electrum" && \
        sudo rm -rf "$FRESH_CLONE" && \
        umask 0022 && \
        git clone "$PROJECT_ROOT" "$FRESH_CLONE" && \
        cd "$FRESH_CLONE"
    git checkout "$ELECBUILD_COMMIT"
    PROJECT_ROOT_OR_FRESHCLONE_ROOT="$FRESH_CLONE"
else
    info "not doing fresh clone."
fi

DOCKER_RUN_FLAGS=""
if [[ -n "$1"  && "$1" == "release" ]] ; then
    info "'release' mode selected. mounting ~/.keystore inside container."
    DOCKER_RUN_FLAGS="-v $HOME/.keystore:/home/user/.keystore"
fi

info "building binary..."
mkdir --parents "$PROJECT_ROOT_OR_FRESHCLONE_ROOT"/.buildozer/.gradle
sudo docker run -it --rm \
    --name electrum-android-builder-cont \
    -v "$PROJECT_ROOT_OR_FRESHCLONE_ROOT":/home/user/wspace/electrum \
    -v "$PROJECT_ROOT_OR_FRESHCLONE_ROOT"/.buildozer/.gradle:/home/user/.gradle \
    $DOCKER_RUN_FLAGS \
    --workdir /home/user/wspace/electrum \
    electrum-android-builder-img \
    ./contrib/android/make_apk "$@"

# make sure resulting binary location is independent of fresh_clone
if [ ! -z "$ELECBUILD_COMMIT" ] ; then
    mkdir --parents "$DISTDIR/"
    sudo cp -f "$FRESH_CLONE/dist"/* "$DISTDIR/"
fi
