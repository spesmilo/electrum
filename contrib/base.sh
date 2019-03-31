#!/usr/bin/env bash

# First, some functions that build scripts may use for pretty printing
RED='\033[0;31m'
BLUE='\033[0,34m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color
function info {
	printf "\r💬 ${BLUE}INFO:${NC}  ${1}\n"
}
function fail {
    printf "\r🗯  ${RED}ERROR:${NC}  ${1}\n"
    exit 1
}
function warn {
	printf "\r⚠️  ${YELLOW}WARNING:${NC}  ${1}\n"
}

# Now, some variables that affect all build scripts

export PYTHONHASHSEED=22
PYTHON_VERSION=3.6.8  # Windows & OSX use this to determine what to download/build
GIT_REPO_ACCT=https://github.com/Electron-Cash  # NOTE: this account should have electrum_local as a repository for the winodws build to work!
GIT_REPO=$GIT_REPO_ACCT/Electron-Cash
GIT_DIR_NAME=`basename $GIT_REPO`
PACKAGE=$GIT_DIR_NAME  # Modify this if you like -- Windows and MacOS build scripts read this
