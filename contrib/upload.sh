#!/bin/bash
# uploadserver is set in /etc/hosts
#
# env vars:
# - ELECBUILD_UPLOADFROM
# - SSHUSER

set -ex

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/.."
CONTRIB="$PROJECT_ROOT/contrib"

if [ -z "$SSHUSER" ]; then
    SSHUSER=thomasv
fi

cd "$PROJECT_ROOT"

VERSION=$("$CONTRIB"/print_electrum_version.py)
echo "$VERSION"

if [ -z "$ELECBUILD_UPLOADFROM" ]; then
    cd "$PROJECT_ROOT/dist"
else
    cd "$ELECBUILD_UPLOADFROM"
fi


# do not fail sftp if directory exists
# see https://stackoverflow.com/questions/51437924/bash-shell-sftp-check-if-directory-exists-before-creating

sftp -oBatchMode=no -b - "$SSHUSER@uploadserver" << !
   cd electrum-downloads-airlock
   -mkdir "$VERSION"
   -chmod 777 "$VERSION"
   cd "$VERSION"
   -mput *
   -chmod 444 *  # this prevents future re-uploads of same file
   bye
!

"$CONTRIB/trigger_deploy.sh" "$SSHUSER" "$VERSION"
