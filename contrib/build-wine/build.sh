#!/bin/bash

here=$(dirname "$0")
test -n "$here" -a -d "$here" || (echo "Cannot determine build dir. FIXME!" && exit 1)

GIT_SUBMODULE_SKIP=1
. "$here"/../base.sh # functions we use below (fail, et al)
unset GIT_SUBMODULE_SKIP

if [ ! -z "$1" ]; then
    REV="$1"
else
    fail "Please specify a release tag or branch to build (eg: master or 4.0.0, etc)"
fi

if [ ! -d 'contrib' ]; then
    fail "Please run this script form the top-level Electron Cash git directory"
fi

pushd .

docker_version=`docker --version`

if [ "$?" != 0 ]; then
    echo ''
    echo "Please install docker by issuing the following commands (assuming you are on Ubuntu):"
    echo ''
    echo '$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -'
    echo '$ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"'
    echo '$ sudo apt-get update'
    echo '$ sudo apt-get install -y docker-ce'
    echo ''
    fail "Docker is required to build for Windows"
fi

set -e

info "Using docker: $docker_version"

# Only set SUDO if its not been set already
if [ -z ${SUDO+x} ] ; then
    SUDO=""  # on macOS (and others?) we don't do sudo for the docker commands ...
    if [ $(uname) = "Linux" ]; then
        # .. on Linux we do
        SUDO="sudo"
    fi
fi

USER_ID=$(id -u $USER)
GROUP_ID=$(id -g $USER)

# To prevent weird errors, img name must capture user:group id since the
# Dockerfile receives those as args and sets up a /homedir in the image
# owned by $USER_ID:$GROUP_ID
IMGNAME="ec-wine-builder-img_${USER_ID}_${GROUP_ID}"

info "Creating docker image ..."
$SUDO docker build -t $IMGNAME \
            --build-arg USER_ID=$USER_ID \
            --build-arg GROUP_ID=$GROUP_ID \
            --build-arg UBUNTU_MIRROR=$UBUNTU_MIRROR \
            contrib/build-wine/docker \
    || fail "Failed to create docker image"

# This is the place where we checkout and put the exact revision we want to work
# on. Docker will run mapping this directory to /homedir/wine64/drive_c/electroncash
# which inside wine will look like c:\electroncash.
FRESH_CLONE=`pwd`/contrib/build-wine/fresh_clone
FRESH_CLONE_DIR="$FRESH_CLONE/$GIT_DIR_NAME"

(
    $SUDO rm -fr "$FRESH_CLONE" && \
        mkdir -p "$FRESH_CLONE" && \
        cd "$FRESH_CLONE"  && \
        git clone "$GIT_REPO" && \
        cd "$GIT_DIR_NAME" && \
        git checkout $REV
) || fail "Could not create a fresh clone from git"

(
    # NOTE: We propagate forward the GIT_REPO override to the container's env,
    # just in case it needs to see it.
    $SUDO docker run $DOCKER_RUN_TTY \
    -u $USER_ID:$GROUP_ID \
    -e HOME=/homedir \
    -e GIT_REPO="$GIT_REPO" \
    -e BUILD_DEBUG="$BUILD_DEBUG" \
    -e PYI_SKIP_TAG="$PYI_SKIP_TAG" \
    --name ec-wine-builder-cont \
    -v "$FRESH_CLONE_DIR":/homedir/wine64/drive_c/electroncash:delegated \
    --rm \
    --workdir /homedir/wine64/drive_c/electroncash/contrib/build-wine \
    $IMGNAME \
    ./_build.sh $REV
) || fail "Build inside docker container failed"

popd

info "Copying .exe files out of our build directory ..."
mkdir -p dist/
files="$FRESH_CLONE_DIR"/contrib/build-wine/dist/*.exe
for f in $files; do
    bn=`basename "$f"`
    cp -fpv "$f" dist/"$bn" || fail "Failed to copy $bn"
    touch dist/"$bn" || fail "Failed to update timestamp on $bn"
done

info "Removing $FRESH_CLONE ..."
$SUDO rm -fr "$FRESH_CLONE"

echo ""
info "Done. Built .exe files have been placed in dist/"
