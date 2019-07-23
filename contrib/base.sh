#!/usr/bin/env bash

# Set a fixed umask as this leaks into the docker container
umask 0022

# First, some functions that build scripts may use for pretty printing
RED='\033[0;31m'
BLUE='\033[0,34m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color
function info {
	printf "\r💬 ${BLUE}INFO:${NC}  ${1}\n"
}
function fail {
    printf "\r🗯  ${RED}ERROR:${NC}  ${1}\n" >&2
    exit 1
}
function warn {
	printf "\r⚠️  ${YELLOW}WARNING:${NC}  ${1}\n"
}
function printok {
    printf "\r👍  ${GREEN}OK:${NC}  ${1}\n"
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

# Now, some variables that affect all build scripts

export PYTHONHASHSEED=22
PYTHON_VERSION=3.6.8  # Windows, OSX & Linux AppImage use this to determine what to download/build
PYTHON_SRC_TARBALL_HASH="35446241e995773b1bed7d196f4b624dadcadc8429f26282e756b2fb8a351193"  # If you change PYTHON_VERSION above, update this by downloading the tarball manually and doing a sha256sum on it.
DEFAULT_GIT_REPO=https://github.com/Electron-Cash/Electron-Cash
if [ -z "$GIT_REPO" ] ; then
    # If no override from env is present, use default. Support for overrides
    # for the GIT_REPO has been added to allows contributors to test containers
    # that are on local filesystem (while devving) or are their own github forks
    GIT_REPO="$DEFAULT_GIT_REPO"
fi
if [ "$GIT_REPO" != "$DEFAULT_GIT_REPO" ]; then
    # We check if it's default because we unconditionally propagate $GIT_REPO
    # in env to _build.sh inside the docker container, and we don't want to
    # print this message if it turns out to just be the default.
    info "Picked up override from env: GIT_REPO=${GIT_REPO}"
fi
GIT_DIR_NAME=`basename $GIT_REPO`
PACKAGE=$GIT_DIR_NAME  # Modify this if you like -- Windows and MacOS build scripts read this
