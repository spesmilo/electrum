#!/bin/bash
#
# This script is used for stage 1 of the release process. It operates exclusively on the airlock.
# This script, for the RELEASEMANAGER (RM):
# - builds and uploads all binaries to airlock,
# - assumes all keys are available, and signs everything
# This script, for other builders:
# - builds all reproducible binaries,
# - downloads binaries built by the release manager (from airlock), compares and signs them,
# - and then uploads sigs
# Note: the .dmg should be built separately beforehand and copied into dist/
#       (as it is built on a separate machine)
#
#
# env vars:
# - ELECBUILD_NOCACHE: if set, forces rebuild of docker images
#
# "uploadserver" is set in /etc/hosts
#
# Note: steps before doing a new release:
# - update locale:
#     1. cd /opt/electrum-locale && ./update.py && git push
#     2. cd to the submodule dir, and git pull
#     3. cd .. && git push
# - update RELEASE-NOTES and version.py
# - $ git tag -s $VERSION -m $VERSION
#
# -----
# Then, typical release flow:
# - RM runs release.sh
# - Another SFTPUSER BUILDER runs `$ ./release.sh`
# - now airlock contains new binaries and two sigs for each
# - deploy.sh will verify sigs and move binaries across airlock
# - new binaries are now publicly available on uploadserver, but not linked from website yet
# - other BUILDERS can now also try to reproduce binaries and open PRs with sigs against spesmilo/electrum-signatures
#   - these PRs can get merged as they come
#   - run add_cosigner
# - after some time, RM can run release_www.sh to create and commit website-update
#   - then run WWW_DIR/publish.sh to update website
# - at least two people need to run WWW_DIR/publish.sh
#

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/.."
CONTRIB="$PROJECT_ROOT/contrib"

cd "$PROJECT_ROOT"

. "$CONTRIB"/build_tools_util.sh

# rm -rf dist/*
# rm -f .buildozer

GPGUSER=$1
if [ -z "$GPGUSER" ]; then
    fail "usage: $0 gpg_username"
fi

export SSHUSER="$GPGUSER"
RELEASEMANAGER=""
if [ "$GPGUSER" == "ThomasV" ]; then
    PUBKEY="--local-user 6694D8DE7BE8EE5631BED9502BD5824B7F9470E6"
    export SSHUSER=thomasv
    RELEASEMANAGER=1
elif [ "$GPGUSER" == "sombernight_releasekey" ]; then
    PUBKEY="--local-user 0EEDCFD5CAFB459067349B23CA9EEEC43DF911DC"
    export SSHUSER=sombernight
else
    warn "unexpected GPGUSER=$GPGUSER"
fi


if [ ! -z "$RELEASEMANAGER" ] ; then
    echo -n "Code signing passphrase:"
    read -s password
    # tests password against keystore
    keytool -list -storepass $password
    # the same password is used for windows signing
    export WIN_SIGNING_PASSWORD=$password
fi


VERSION=$("$CONTRIB"/print_electrum_version.py)
APK_VERSION=$("$CONTRIB"/print_electrum_version.py APK_VERSION)
info "VERSION: $VERSION"
info "APK_VERSION: $APK_VERSION"
REV=$(git describe --tags)
info "REV: $REV"
COMMIT=$(git rev-parse HEAD)

export ELECBUILD_COMMIT="${COMMIT}^{commit}"


git_status=$(git status --porcelain)
if [ ! -z "$git_status" ]; then
    echo "$git_status"
    fail "git repo not clean, aborting"
fi

set -x

# create tarball
tarball="Electrum-$VERSION.tar.gz"
if test -f "dist/$tarball"; then
    info "file exists: $tarball"
else
    ./contrib/build-linux/sdist/build.sh
fi

# create source-only tarball
srctarball="Electrum-sourceonly-$VERSION.tar.gz"
if test -f "dist/$srctarball"; then
    info "file exists: $srctarball"
else
    OMIT_UNCLEAN_FILES=1 ./contrib/build-linux/sdist/build.sh
fi

# appimage
appimage="electrum-$REV-x86_64.AppImage"
if test -f "dist/$appimage"; then
    info "file exists: $appimage"
else
    ./contrib/build-linux/appimage/build.sh
fi


# windows
win1="electrum-$REV.exe"
win2="electrum-$REV-portable.exe"
win3="electrum-$REV-setup.exe"
if test -f "dist/$win1"; then
    info "file exists: $win1"
else
    pushd .
    if test -f "contrib/build-wine/dist/$win1"; then
        info "unsigned file exists: $win1"
    else
        ./contrib/build-wine/build.sh
    fi
    cd contrib/build-wine/
    if [ ! -z "$RELEASEMANAGER" ] ; then
        ./sign.sh
        cp ./signed/*.exe "$PROJECT_ROOT/dist/"
    else
        cp ./dist/*.exe "$PROJECT_ROOT/dist/"
    fi
    popd
fi

# android
apk1="Electrum-$APK_VERSION-armeabi-v7a-release.apk"
apk2="Electrum-$APK_VERSION-arm64-v8a-release.apk"
apk3="Electrum-$APK_VERSION-x86_64-release.apk"
for arch in armeabi-v7a arm64-v8a x86_64
do
    apk="Electrum-$APK_VERSION-$arch-release.apk"
    apk_unsigned="Electrum-$APK_VERSION-$arch-release-unsigned.apk"
    if test -f "dist/$apk"; then
        info "file exists: $apk"
    else
        info "file does not exists: $apk"
        if [ ! -z "$RELEASEMANAGER" ] ; then
            ./contrib/android/build.sh qml $arch release $password
        else
            ./contrib/android/build.sh qml $arch release-unsigned
            mv "dist/$apk_unsigned" "dist/$apk"
        fi
    fi
done

# the macos binary is built on a separate machine.
# the file that needs to be copied over is the codesigned release binary (regardless of builder role)
dmg="electrum-$VERSION.dmg"
if ! test -f "dist/$dmg"; then
    if [ ! -z "$RELEASEMANAGER" ] ; then  # RM
        fail "dmg is missing, aborting. Please build and codesign the dmg on a mac and copy it over."
    else  # other builders
        fail "dmg is missing, aborting. Please build the unsigned dmg on a mac, compare it with file built by RM, and if matches, copy RM's dmg."
    fi
fi

# now that we have all binaries, if we are the RM, sign them.
if [ ! -z "$RELEASEMANAGER" ] ; then
    if test -f "dist/$dmg.asc"; then
        info "packages are already signed"
    else
        info "signing packages"
        ./contrib/sign_packages "$GPGUSER"
    fi
fi

info "build complete"
sha256sum dist/*.tar.gz
sha256sum dist/*.AppImage
sha256sum contrib/build-wine/dist/*.exe

echo -n "proceed (y/n)? "
read answer

if [ "$answer" != "y" ]; then
    echo "exit"
    exit 1
fi


if [ -z "$RELEASEMANAGER" ] ; then
    # people OTHER THAN release manager.
    # download binaries built by RM
    rm -rf "$PROJECT_ROOT/dist/releasemanager"
    mkdir --parent "$PROJECT_ROOT/dist/releasemanager"
    cd "$PROJECT_ROOT/dist/releasemanager"
    # TODO check somehow that RM had finished uploading
    sftp -oBatchMode=no -b - "$SSHUSER@uploadserver" << !
       cd electrum-downloads-airlock
       cd "$VERSION"
       mget *
       bye
!
    # check we have each binary
    test -f "$tarball"    || fail "tarball not found among sftp downloads"
    test -f "$srctarball" || fail "srctarball not found among sftp downloads"
    test -f "$appimage"   || fail "appimage not found among sftp downloads"
    test -f "$win1"       || fail "win1 not found among sftp downloads"
    test -f "$win2"       || fail "win2 not found among sftp downloads"
    test -f "$win3"       || fail "win3 not found among sftp downloads"
    test -f "$apk1"       || fail "apk1 not found among sftp downloads"
    test -f "$apk2"       || fail "apk2 not found among sftp downloads"
    test -f "$apk3"       || fail "apk3 not found among sftp downloads"
    test -f "$dmg"        || fail "dmg not found among sftp downloads"
    test -f "$PROJECT_ROOT/dist/$tarball"    || fail "tarball not found among built files"
    test -f "$PROJECT_ROOT/dist/$srctarball" || fail "srctarball not found among built files"
    test -f "$PROJECT_ROOT/dist/$appimage"   || fail "appimage not found among built files"
    test -f "$CONTRIB/build-wine/dist/$win1" || fail "win1 not found among built files"
    test -f "$CONTRIB/build-wine/dist/$win2" || fail "win2 not found among built files"
    test -f "$CONTRIB/build-wine/dist/$win3" || fail "win3 not found among built files"
    test -f "$PROJECT_ROOT/dist/$apk1"       || fail "apk1 not found among built files"
    test -f "$PROJECT_ROOT/dist/$apk2"       || fail "apk2 not found among built files"
    test -f "$PROJECT_ROOT/dist/$apk3"       || fail "apk3 not found among built files"
    test -f "$PROJECT_ROOT/dist/$dmg"        || fail "dmg not found among built files"
    # compare downloaded binaries against ones we built
    cmp --silent "$tarball"    "$PROJECT_ROOT/dist/$tarball"    || fail "files are different. tarball."
    cmp --silent "$srctarball" "$PROJECT_ROOT/dist/$srctarball" || fail "files are different. srctarball."
    cmp --silent "$appimage"   "$PROJECT_ROOT/dist/$appimage"   || fail "files are different. appimage."
    rm -rf "$CONTRIB/build-wine/signed/" && mkdir --parents "$CONTRIB/build-wine/signed/"
    cp -f "$win1" "$win2" "$win3" "$CONTRIB/build-wine/signed/"
    "$CONTRIB/build-wine/unsign.sh" || fail "files are different. windows."
    "$CONTRIB/android/apkdiff.py" "$apk1" "$PROJECT_ROOT/dist/$apk1" || fail "files are different. android."
    "$CONTRIB/android/apkdiff.py" "$apk2" "$PROJECT_ROOT/dist/$apk2" || fail "files are different. android."
    "$CONTRIB/android/apkdiff.py" "$apk3" "$PROJECT_ROOT/dist/$apk3" || fail "files are different. android."
    cmp --silent "$dmg" "$PROJECT_ROOT/dist/$dmg" || fail "files are different. macos."
    # all files matched. sign them.
    rm -rf "$PROJECT_ROOT/dist/sigs/"
    mkdir --parents "$PROJECT_ROOT/dist/sigs/"
    for fname in "$tarball" "$srctarball" "$appimage" "$win1" "$win2" "$win3" "$apk1" "$apk2" "$apk3" "$dmg" ; do
        signame="$fname.$GPGUSER.asc"
        gpg --sign --armor --detach $PUBKEY --output "$PROJECT_ROOT/dist/sigs/$signame" "$fname"
    done
    # upload sigs
    ELECBUILD_UPLOADFROM="$PROJECT_ROOT/dist/sigs/" "$CONTRIB/upload.sh"

else
    # ONLY release manager

    cd "$PROJECT_ROOT"

    # check we have each binary
    test -f "$PROJECT_ROOT/dist/$tarball"    || fail "tarball not found among built files"
    test -f "$PROJECT_ROOT/dist/$srctarball" || fail "srctarball not found among built files"
    test -f "$PROJECT_ROOT/dist/$appimage"   || fail "appimage not found among built files"
    test -f "$PROJECT_ROOT/dist/$win1"       || fail "win1 not found among built files"
    test -f "$PROJECT_ROOT/dist/$win2"       || fail "win2 not found among built files"
    test -f "$PROJECT_ROOT/dist/$win3"       || fail "win3 not found among built files"
    test -f "$PROJECT_ROOT/dist/$apk1"       || fail "apk1 not found among built files"
    test -f "$PROJECT_ROOT/dist/$apk2"       || fail "apk2 not found among built files"
    test -f "$PROJECT_ROOT/dist/$apk3"       || fail "apk3 not found among built files"
    test -f "$PROJECT_ROOT/dist/$dmg"        || fail "dmg not found among built files"

    if [ $REV != $VERSION ]; then
        fail "versions differ, not uploading"
    fi

    # upload the files
    ./contrib/upload.sh

fi


info "release.sh finished successfully."
info "After two people ran release.sh, the binaries will be publicly available on uploadserver."
info "Then, we wait for additional signers, and run add_cosigner for them."
info "Finally, release_www.sh needs to be run, for the website to be updated."
