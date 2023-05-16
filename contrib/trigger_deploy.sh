#!/bin/bash
# Triggers deploy.sh to maybe update the website or move binaries.
# uploadserver needs to be defined in /etc/hosts

SSHUSER=$1
TRIGGERVERSION=$2
if [ -z "$SSHUSER" ] || [ -z "$TRIGGERVERSION" ]; then
    echo "usage: $0 SSHUSER TRIGGERVERSION"
    echo "e.g. $0 thomasv 3.0.0"
    echo "e.g. $0 thomasv website"
    exit 1
fi
set -ex
cd "$(dirname "$0")"

if [ "$TRIGGERVERSION" == "website" ]; then
    rm -f trigger_website
    touch trigger_website
    echo "uploading file: trigger_website..."
    sftp -oBatchMode=no -b - "$SSHUSER@uploadserver" << !
       cd electrum-downloads-airlock
       mput trigger_website
       bye
!
else
    rm -f trigger_binaries
    printf "$TRIGGERVERSION" > trigger_binaries
    echo "uploading file: trigger_binaries..."
    sftp -oBatchMode=no -b - "$SSHUSER@uploadserver" << !
       cd electrum-downloads-airlock
       mput trigger_binaries
       bye
!
fi

