#!/usr/bin/env bash

# Set a fixed umask as this leaks into docker containers
umask 0022

RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color
function info {
    printf "\r💬 ${BLUE}INFO:${NC}  ${1}\n"
}
function fail {
    printf "\r🗯 ${RED}ERROR:${NC} ${1}\n"
    exit 1
}
function warn {
    printf "\r⚠️  ${YELLOW}WARNING:${NC}  ${1}\n"
}


# based on https://superuser.com/questions/497940/script-to-verify-a-signature-with-gpg
function verify_signature() {
    local file=$1 keyring=$2 out=
    if out=$(gpg --no-default-keyring --keyring "$keyring" --status-fd 1 --verify "$file" 2>/dev/null) &&
       echo "$out" | grep -qs "^\[GNUPG:\] VALIDSIG "; then
        return 0
    else
        echo "$out" >&2
        exit 1
    fi
}

function verify_hash() {
    local file=$1 expected_hash=$2
    actual_hash=$(sha256sum $file | awk '{print $1}')
    if [ "$actual_hash" == "$expected_hash" ]; then
        return 0
    else
        echo "$file $actual_hash (unexpected hash)" >&2
        rm "$file"
        exit 1
    fi
}

function download_if_not_exist() {
    local file_name=$1 url=$2
    if [ ! -e $file_name ] ; then
        wget -O $file_name "$url"
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
