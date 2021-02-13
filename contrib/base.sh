#!/usr/bin/env bash

# Set BUILD_DEBUG=1 to enable additional build output
if [ "${BUILD_DEBUG:-0}" -ne 0 ] ; then
    set -x # Enable shell command logging
fi

# Set a fixed umask as this leaks into the docker container
umask 0022

# First, some functions that build scripts may use for pretty printing
if [ -t 1 ] ; then
    RED='\033[0;31m'
    BLUE='\033[0;34m'
    YELLOW='\033[0;33m'
    GREEN='\033[0;32m'
    NC='\033[0m' # No Color

    MSG_INFO="\r💬 ${BLUE}INFO:${NC}"
    MSG_ERROR="\r🗯  ${RED}ERROR:${NC}"
    MSG_WARNING="\r⚠️  ${YELLOW}WARNING:${NC}"
    MSG_OK="\r👍  ${GREEN}OK:${NC}"
else
    RED=''
    BLUE=''
    YELLOW=''
    GREEN=''
    NC='' # No Color

    MSG_INFO="INFO:"
    MSG_ERROR="ERROR:"
    MSG_WARNING="WARNING:"
    MSG_OK="OK:"
fi

function info {
    printf "${MSG_INFO}  ${1}\n"
}
function fail {
    printf "${MSG_ERROR}  ${1}\n" >&2

    if [ -r /.dockerenv ] ; then
        if [ -t 1 ] ; then
            if [ "${BUILD_DEBUG:-0}" -ne 0 ] ; then
                bash || true
            fi
        fi
    fi

    exit 1
}
function warn {
    printf "${MSG_WARNING}  ${1}\n"
}
function printok {
    printf "${MSG_OK}  ${1}\n"
}

function verify_hash {
    local file=$1 expected_hash=$2
    sha_prog=`which sha256sum || which gsha256sum`
    if [ -z "$sha_prog" ]; then
        fail "Please install sha256sum or gsha256sum"
    fi
    if [ ! -e "$file" ]; then
        fail "Cannot verify hash for $file -- not found!"
    fi
    bn=`basename $file`
    actual_hash=$($sha_prog $file | awk '{print $1}')
    if [ "$actual_hash" == "$expected_hash" ]; then
        printok "'$bn' hash verified"
        return 0
    else
        warn "Hash verify failed, removing '$file' as a safety measure"
        rm "$file"
        fail "$file $actual_hash (unexpected hash)"
    fi
}

# based on https://superuser.com/questions/497940/script-to-verify-a-signature-with-gpg
function verify_signature {
    local file=$1 keyring=$2 out=
    bn=`basename $file .asc`
    info "Verifying PGP signature for $bn ..."
    if out=$(gpg --no-default-keyring --keyring "$keyring" --status-fd 1 --verify "$file" 2>/dev/null) \
            && echo "$out" | grep -qs "^\[GNUPG:\] VALIDSIG "; then
        printok "$bn signature verified"
        return 0
    else
        fail "$out"
    fi
}

function download_if_not_exist() {
    local file_name=$1 url=$2
    if [ ! -e $file_name ] ; then
        if [ -n "$(which wget)" ]; then
            wget -O $file_name "$url" || fail "Failed to download $file_name"
        else
            curl -L "$url" > $file_name || fail "Failed to download $file_name"
        fi
    fi

}

# https://github.com/travis-ci/travis-build/blob/master/lib/travis/build/templates/header.sh
function retry() {
  local result=0
  local count=1
  while [ $count -le 3 ]; do
    [ $result -ne 0 ] && {
      echo -e "\nThe command \"$@\" failed. Retrying, $count of 3.\n" >&2
    }
    ! { "$@"; result=$?; }
    [ $result -eq 0 ] && break
    count=$(($count + 1))
    sleep 1
  done

  [ $count -gt 3 ] && {
    echo -e "\nThe command \"$@\" failed 3 times.\n" >&2
  }

  return $result
}

function gcc_with_triplet()
{
    TRIPLET="$1"
    CMD="$2"
    shift 2
    if [ -n "$TRIPLET" ] ; then
        "$TRIPLET-$CMD" "$@"
    else
        "$CMD" "$@"
    fi
}

function gcc_host()
{
    gcc_with_triplet "$GCC_TRIPLET_HOST" "$@"
}

function gcc_build()
{
    gcc_with_triplet "$GCC_TRIPLET_BUILD" "$@"
}

function host_strip()
{
    if [ "$GCC_STRIP_BINARIES" -ne "0" ] ; then
        case "$BUILD_TYPE" in
            linux|wine)
                gcc_host strip "$@"
                ;;
            darwin)
                # TODO: Strip on macOS?
                ;;
        esac
    fi
}

# From: https://stackoverflow.com/a/4024263
# By kanaka (https://stackoverflow.com/users/471795/)
function verlte()
{
    [  "$1" = "`echo -e "$1\n$2" | $SORT_PROG -V | head -n1`" ]
}

function verlt()
{
    [ "$1" = "$2" ] && return 1 || verlte $1 $2
}

function git_describe_filtered()
{
    if [ ! -z ${1+x} ] ; then
        git describe --tags --match "$1" --dirty --always
    else
        git describe --tags --exclude 'android-*' --exclude 'ios_*' --dirty --always
    fi
}

if [ -n "$_BASE_SH_SOURCED" ] ; then
    # Base.sh has been sourced already, no need to source it again
    return 0
fi

which git > /dev/null || fail "Git is required to proceed"

# Now, some variables that affect all build scripts

export PYTHONHASHSEED=22
export SOURCE_DATE_EPOCH=1530212462
# Note, when upgrading Python, check the Windows python.exe embedded manifest for changes.
# If the manifest changed, contrib/build-wine/manifest.xml needs to be updated.
export PYTHON_VERSION=3.8.7  # Windows, OSX & Linux AppImage use this to determine what to download/build
export PYTHON_SRC_TARBALL_HASH="ddcc1df16bb5b87aa42ec5d20a5b902f2d088caa269b28e01590f97a798ec50a"  # If you change PYTHON_VERSION above, update this by downloading the tarball manually and doing a sha256sum on it.
export DEFAULT_GIT_REPO=https://github.com/Electron-Cash/Electron-Cash
if [ -z "$GIT_REPO" ] ; then
    # If no override from env is present, use default. Support for overrides
    # for the GIT_REPO has been added to allows contributors to test containers
    # that are on local filesystem (while devving) or are their own github forks
    export GIT_REPO="$DEFAULT_GIT_REPO"
fi
if [ "$GIT_REPO" != "$DEFAULT_GIT_REPO" ]; then
    # We check if it's default because we unconditionally propagate $GIT_REPO
    # in env to _build.sh inside the docker container, and we don't want to
    # print this message if it turns out to just be the default.
    info "Picked up override from env: GIT_REPO=${GIT_REPO}"
fi
export GIT_DIR_NAME=`basename $GIT_REPO`
export PACKAGE="Electron-Cash"  # Modify this if you like -- Windows, MacOS & Linux srcdist build scripts read this, while AppImage has it hard-coded
export PYI_SKIP_TAG="${PYI_SKIP_TAG:-0}" # Set this to non-zero to make PyInstaller skip tagging the bootloader
export DEFAULT_UBUNTU_MIRROR="http://archive.ubuntu.com/ubuntu/"
export UBUNTU_MIRROR="${UBUNTU_MIRROR:-$DEFAULT_UBUNTU_MIRROR}"
if [ "$UBUNTU_MIRROR" != "$DEFAULT_UBUNTU_MIRROR" ]; then
    info "Picked up override from env: UBUNTU_MIRROR=${UBUNTU_MIRROR}"
fi

# Build a command line argument for docker, enabling interactive mode if stdin
# is a tty and enabling tty in docker if stdout is a tty.
export DOCKER_RUN_TTY=""
if [ -t 0 ] ; then export DOCKER_RUN_TTY="${DOCKER_RUN_TTY}i" ; fi
if [ -t 1 ] ; then export DOCKER_RUN_TTY="${DOCKER_RUN_TTY}t" ; fi
if [ -n "$DOCKER_RUN_TTY" ] ; then export DOCKER_RUN_TTY="-${DOCKER_RUN_TTY}" ; fi

if [ -z "$CPU_COUNT" ] ; then
    # CPU_COUNT is not set, try to detect the core count
    case $(uname) in
        Linux)
            export CPU_COUNT=$(lscpu | grep "^CPU(s):" | awk '{print $2}')
            ;;
        Darwin)
            export CPU_COUNT=$(sysctl -n hw.ncpu)
            ;;
    esac
fi
# If CPU_COUNT is still unset, default to 4
export CPU_COUNT="${CPU_COUNT:-4}"
# Use one more worker than core count
export WORKER_COUNT=$[$CPU_COUNT+1]
# Set the build type, overridden by wine build
export BUILD_TYPE="${BUILD_TYPE:-$(uname | tr '[:upper:]' '[:lower:]')}"
# No additional autoconf flags by default
export AUTOCONF_FLAGS=""
# Add host / build flags if the triplets are set
if [ -n "$GCC_TRIPLET_HOST" ] ; then
    export AUTOCONF_FLAGS="$AUTOCONF_FLAGS --host=$GCC_TRIPLET_HOST"
fi
if [ -n "$GCC_TRIPLET_BUILD" ] ; then
    export AUTOCONF_FLAGS="$AUTOCONF_FLAGS --build=$GCC_TRIPLET_BUILD"
fi

export GCC_STRIP_BINARIES="${GCC_STRIP_BINARIES:-0}"

export SHA256_PROG=`which sha256sum || which gsha256sum`
if [ -z "$SHA256_PROG" ]; then
    fail "Please install sha256sum or gsha256sum"
fi

export SORT_PROG=`which gsort || which sort`
if [ -z "$SORT_PROG" ]; then
    fail "Please install sort or gsort"
fi

if [ "${GIT_SUBMODULE_SKIP:-0}" -eq 0 ] ; then
    info "Refreshing submodules ($GIT_SUBMODULE_FLAGS)..."
    gitflags=""
    if ! verlt $(git --version | awk '{print $3}') 2.18.0 ; then
        # For shallow clones to work with git versions >= 2.22.0 we need to ensure we
        # use git protocol version 2, which is available starting with version 2.18.0.
        # See https://public-inbox.org/git/20191013064314.GA28018@sigill.intra.peff.net/
        gitflags="-c protocol.version=2"
    fi
    git $gitflags submodule update --init --jobs 0 $GIT_SUBMODULE_FLAGS || fail "Failed to update git submodules"
fi

# This variable is set to avoid sourcing base.sh multiple times
export _BASE_SH_SOURCED=1
