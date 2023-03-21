#!/bin/bash
#
# env vars:
# - ELECBUILD_NOCACHE: if set, forces rebuild of docker image
# - ELECBUILD_COMMIT: if set, do a fresh clone and git checkout

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../../.."
PROJECT_ROOT_OR_FRESHCLONE_ROOT="$PROJECT_ROOT"
CONTRIB="$PROJECT_ROOT/contrib"
CONTRIB_SDIST="$CONTRIB/build-linux/sdist"
DISTDIR="$PROJECT_ROOT/dist"
BUILD_UID=$(/usr/bin/stat -c %u "$PROJECT_ROOT")

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
    -t electrum-sdist-builder-img \
    "$CONTRIB_SDIST"

# maybe do fresh clone
if [ ! -z "$ELECBUILD_COMMIT" ] ; then
    info "ELECBUILD_COMMIT=$ELECBUILD_COMMIT. doing fresh clone and git checkout."
    FRESH_CLONE="/tmp/electrum_build/sdist/fresh_clone/electrum"
    rm -rf "$FRESH_CLONE" 2>/dev/null || ( info "we need sudo to rm prev FRESH_CLONE." && sudo rm -rf "$FRESH_CLONE" )
    umask 0022
    git clone "$PROJECT_ROOT" "$FRESH_CLONE"
    cd "$FRESH_CLONE"
    git checkout "$ELECBUILD_COMMIT"
    PROJECT_ROOT_OR_FRESHCLONE_ROOT="$FRESH_CLONE"
else
    info "not doing fresh clone."
fi

info "building binary..."
# check uid and maybe chown. see #8261
if [ ! -z "$ELECBUILD_COMMIT" ] ; then  # fresh clone (reproducible build)
    if [ $(id -u) != "1000" ] || [ $(id -g) != "1000" ] ; then
        info "need to chown -R FRESH_CLONE dir. prompting for sudo."
        sudo chown -R 1000:1000 "$FRESH_CLONE"
    fi
fi
docker run -it \
    --name electrum-sdist-builder-cont \
    -v "$PROJECT_ROOT_OR_FRESHCLONE_ROOT":/opt/electrum \
    --rm \
    --workdir /opt/electrum/contrib/build-linux/sdist \
    --env OMIT_UNCLEAN_FILES \
    electrum-sdist-builder-img \
    ./make_sdist.sh

# make sure resulting binary location is independent of fresh_clone
if [ ! -z "$ELECBUILD_COMMIT" ] ; then
    mkdir --parents "$DISTDIR/"
    cp -f "$FRESH_CLONE/dist"/* "$DISTDIR/"
fi
