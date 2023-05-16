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

# check arguments
if [[ -n "$3" \
	  && ( "$1" == "kivy" || "$1" == "qml" ) \
	  && ( "$2" == "all"  || "$2" == "armeabi-v7a" || "$2" == "arm64-v8a" || "$2" == "x86" ) \
	  && ( "$3" == "debug"  || "$3" == "release" || "$3" == "release-unsigned" ) ]] ; then
    info "arguments $*"
else
    fail "usage: build.sh <kivy|qml> <arm64-v8a|armeabi-v7a|x86|all> <debug|release|release-unsigned>"
    exit 1
fi

# create symlink
rm -f ${PROJECT_ROOT}/.buildozer
mkdir -p "${PROJECT_ROOT}/.buildozer_$1"
ln -s ".buildozer_$1" ${PROJECT_ROOT}/.buildozer

DOCKER_BUILD_FLAGS=""
if [ ! -z "$ELECBUILD_NOCACHE" ] ; then
    info "ELECBUILD_NOCACHE is set. forcing rebuild of docker image."
    DOCKER_BUILD_FLAGS="--pull --no-cache"
fi

info "building docker image."
docker build \
    $DOCKER_BUILD_FLAGS \
    -t electrum-android-builder-img \
    --file "$CONTRIB_ANDROID/Dockerfile" \
    "$PROJECT_ROOT"


# maybe do fresh clone
if [ ! -z "$ELECBUILD_COMMIT" ] ; then
    info "ELECBUILD_COMMIT=$ELECBUILD_COMMIT. doing fresh clone and git checkout."
    FRESH_CLONE="$CONTRIB_ANDROID/fresh_clone/electrum" && \
        rm -rf "$FRESH_CLONE" && \
        umask 0022 && \
        git clone "$PROJECT_ROOT" "$FRESH_CLONE" && \
        cd "$FRESH_CLONE"
    git checkout "$ELECBUILD_COMMIT"
    PROJECT_ROOT_OR_FRESHCLONE_ROOT="$FRESH_CLONE"
else
    info "not doing fresh clone."
fi

DOCKER_RUN_FLAGS=""

if [[ "$3" == "release" ]] ; then
    info "'release' mode selected. mounting ~/.keystore inside container."
    DOCKER_RUN_FLAGS="-v $HOME/.keystore:/home/user/.keystore"
fi

info "building binary..."
mkdir --parents "$PROJECT_ROOT_OR_FRESHCLONE_ROOT"/.buildozer/.gradle
docker run -it --rm \
    --name electrum-android-builder-cont \
    -v "$PROJECT_ROOT_OR_FRESHCLONE_ROOT":/home/user/wspace/electrum \
    -v "$PROJECT_ROOT_OR_FRESHCLONE_ROOT"/.buildozer/.gradle:/home/user/.gradle \
    $DOCKER_RUN_FLAGS \
    --workdir /home/user/wspace/electrum \
    electrum-android-builder-img \
    ./contrib/android/make_apk.sh "$@"

# make sure resulting binary location is independent of fresh_clone
if [ ! -z "$ELECBUILD_COMMIT" ] ; then
    mkdir --parents "$DISTDIR/"
    cp -f "$FRESH_CLONE/dist"/* "$DISTDIR/"
fi
