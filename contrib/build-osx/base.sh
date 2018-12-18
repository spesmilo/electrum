#!/usr/bin/env bash

RED='\033[0;31m'
BLUE='\033[0,34m'
NC='\033[0m' # No Color
function info {
	printf "\r💬 ${BLUE}INFO:${NC}  ${1}\n"
}
function fail {
    printf "\r🗯 ${RED}ERROR:${NC} ${1}\n"
    exit 1
}
