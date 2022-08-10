#!/bin/sh

# Run this after a new release to update pin for build container distro packages

set -e

DEBIAN_SNAPSHOT_BASE="https://snapshot.debian.org/archive/debian/"
DEBIAN_DISTRO="buster" # should match Dockerfile base

contrib=$(dirname "$0")


if [ ! -x /bin/wget ]; then
  echo "no wget"
  exit 1
fi

DEBIAN_SNAPSHOT_LATEST=$(wget -O- ${DEBIAN_SNAPSHOT_BASE}$(date +"?year=%Y&month=%m") 2>/dev/null|grep "^<a href=\"20"|tail -1|sed -e 's#[^"]*"\(.\{17,17\}\).*#\1#')

if [ "${DEBIAN_SNAPSHOT_LATEST}x" = "x" ]; then
  echo "could not find timestamp for debian packages"
  exit 1
fi

echo "Checking if URL valid.."
wget -O /dev/null ${DEBIAN_SNAPSHOT_BASE}${DEBIAN_SNAPSHOT_LATEST} 2>/dev/null

echo "Valid!"

echo "deb ${DEBIAN_SNAPSHOT_BASE}${DEBIAN_SNAPSHOT_LATEST} ${DEBIAN_DISTRO} main non-free contrib" >$contrib/build-linux/appimage/apt.sources.list
echo "deb-src ${DEBIAN_SNAPSHOT_BASE}${DEBIAN_SNAPSHOT_LATEST} ${DEBIAN_DISTRO} main non-free contrib" >>$contrib/build-linux/appimage/apt.sources.list

echo "updated APT sources to ${DEBIAN_SNAPSHOT_BASE}${DEBIAN_SNAPSHOT_LATEST}"
