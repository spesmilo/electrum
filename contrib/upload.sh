#!/bin/bash
# uploadserver is set in /etc/hosts
#
# env vars:
# - ELECBUILD_UPLOADFROM
# - SSHUSER

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/.."

if [ -z "$SSHUSER" ]; then
    SSHUSER=thomasv
fi

cd "$PROJECT_ROOT"

version=$(git describe --tags --abbrev=0)
echo $version

if [ -z "$ELECBUILD_UPLOADFROM" ]; then
    cd "$PROJECT_ROOT/dist"
else
    cd "$ELECBUILD_UPLOADFROM"
fi


# do not fail sftp if directory exists
# see https://stackoverflow.com/questions/51437924/bash-shell-sftp-check-if-directory-exists-before-creating

sftp -oBatchMode=no -b - "$SSHUSER@uploadserver" << !
   cd electrum-downloads-airlock
   -mkdir "$version"
   -chmod 777 "$version"
   cd "$version"
   mput *
   bye
!
