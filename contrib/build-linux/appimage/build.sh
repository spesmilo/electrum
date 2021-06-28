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
BUILDDIR="$CONTRIB_APPIMAGE/build/appimage"
APPDIR="$BUILDDIR/NavCash.AppDir"
CACHEDIR="$CONTRIB_APPIMAGE/.cache/appimage"
PIP_CACHE_DIR="$CACHEDIR/pip_cache"

export GCC_STRIP_BINARIES="1"

# pinned versions
# note: compiling python 3.8.x requires at least glibc 2.27,
#       which is first available on ubuntu 18.04
PYTHON_VERSION=3.7.10
PKG2APPIMAGE_COMMIT="eb8f3acdd9f11ab19b78f5cb15daa772367daf15"
SQUASHFSKIT_COMMIT="ae0d656efa2d0df2fcac795b6823b44462f19386"


VERSION=`git describe --tags --dirty --always`
APPIMAGE="$DISTDIR/NavCash-$VERSION-x86_64.AppImage"

. "$CONTRIB"/build_tools_util.sh


DOCKER_BUILD_FLAGS=""
if [ ! -z "$ELECBUILD_NOCACHE" ] ; then
    info "ELECBUILD_NOCACHE is set. forcing rebuild of docker image."
    DOCKER_BUILD_FLAGS="--pull --no-cache"
fi

info "building docker image."
sudo docker build \
    $DOCKER_BUILD_FLAGS \
    -t electrum-appimage-builder-img \
    "$CONTRIB_APPIMAGE"

# maybe do fresh clone
if [ ! -z "$ELECBUILD_COMMIT" ] ; then
    info "ELECBUILD_COMMIT=$ELECBUILD_COMMIT. doing fresh clone and git checkout."
    FRESH_CLONE="$CONTRIB_APPIMAGE/fresh_clone/electrum" && \
        sudo rm -rf "$FRESH_CLONE" && \
        umask 0022 && \
        git clone "$PROJECT_ROOT" "$FRESH_CLONE" && \
        cd "$FRESH_CLONE"
    git checkout "$ELECBUILD_COMMIT"
    PROJECT_ROOT_OR_FRESHCLONE_ROOT="$FRESH_CLONE"
else
    info "not doing fresh clone."
fi

info "building binary..."
sudo docker run -it \
    --name electrum-appimage-builder-cont \
    -v "$PROJECT_ROOT_OR_FRESHCLONE_ROOT":/opt/electrum \
    --rm \
    --workdir /opt/electrum/contrib/build-linux/appimage \
    electrum-appimage-builder-img \
    ./make_appimage.sh

# make sure resulting binary location is independent of fresh_clone
if [ ! -z "$ELECBUILD_COMMIT" ] ; then
    mkdir --parents "$DISTDIR/"
    sudo cp -f "$FRESH_CLONE/dist"/* "$DISTDIR/"
fi
