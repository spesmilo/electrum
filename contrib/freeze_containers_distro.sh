#!/bin/sh

# Run this after a new release to update pin for build container distro packages

set -e

DEBIAN_SNAPSHOT_BASE="https://snapshot.debian.org/archive/debian/"
DEBIAN_APPIMAGE_DISTRO="buster"  # should match build-linux/appimage Dockerfile base
DEBIAN_WINE_DISTRO="bookworm"    # should match build-wine Dockerfile base
DEBIAN_ANDROID_DISTRO="bookworm" # should match android Dockerfile base

contrib=$(dirname "$0")


if [ ! -x /bin/wget ]; then
    echo "no wget"
    exit 1
fi

DEBIAN_SNAPSHOT_LATEST=$(wget -O- ${DEBIAN_SNAPSHOT_BASE}$(date +"?year=%Y&month=%m") 2>/dev/null | grep "^<a href=\"20" | tail -1 | sed -e 's#[^"]*"\(.\{17,17\}\).*#\1#')

if [ "${DEBIAN_SNAPSHOT_LATEST}x" = "x" ]; then
    echo "could not find timestamp for debian packages"
    exit 1
fi

DEBIAN_SNAPSHOT=${DEBIAN_SNAPSHOT_BASE}${DEBIAN_SNAPSHOT_LATEST}

echo "Checking if URL valid.."
wget -O /dev/null ${DEBIAN_SNAPSHOT} 2>/dev/null

echo "Valid!"

# build-linux
echo "deb ${DEBIAN_SNAPSHOT} ${DEBIAN_APPIMAGE_DISTRO} main" >$contrib/build-linux/appimage/apt.sources.list
echo "deb-src ${DEBIAN_SNAPSHOT} ${DEBIAN_APPIMAGE_DISTRO} main" >>$contrib/build-linux/appimage/apt.sources.list

# build-wine
echo "deb ${DEBIAN_SNAPSHOT} ${DEBIAN_WINE_DISTRO} main" >$contrib/build-wine/apt.sources.list
echo "deb-src ${DEBIAN_SNAPSHOT} ${DEBIAN_WINE_DISTRO} main" >>$contrib/build-wine/apt.sources.list

# android
echo "deb ${DEBIAN_SNAPSHOT} ${DEBIAN_ANDROID_DISTRO} main" >$contrib/android/apt.sources.list
echo "deb-src ${DEBIAN_SNAPSHOT} ${DEBIAN_ANDROID_DISTRO} main" >>$contrib/android/apt.sources.list

echo "updated APT sources to ${DEBIAN_SNAPSHOT}"
