#!/bin/bash
#
# This script, for the RELEASEMANAGER:
# - builds and uploads all binaries,
# - assumes all keys are available, and signs everything
# This script, for other builders:
# - builds all reproducible binaries,
# - downloads binaries built by the release manager, compares and signs them,
# - and then uploads sigs
# Note: the .dmg should be built separately beforehand and copied into dist/
#       (as it is built on a separate machine)
#
# env vars:
# - ELECBUILD_NOCACHE: if set, forces rebuild of docker images
# - WWW_DIR: path to "electrum-web" git clone
#
# additional env vars for the RELEASEMANAGER:
# - for signing the version announcement file:
#   - ELECTRUM_SIGNING_ADDRESS (required)
#   - ELECTRUM_SIGNING_WALLET (required)
#
# "uploadserver" is set in /etc/hosts
#
# Note: steps before doing a new release:
# - update locale:
#     1. cd /opt/electrum-locale && ./update && push
#     2. cd to the submodule dir, and git pull
#     3. cd .. && git push
# - update RELEASE-NOTES and version.py
# - git tag
#

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/.."
CONTRIB="$PROJECT_ROOT/contrib"

cd "$PROJECT_ROOT"

. "$CONTRIB"/build_tools_util.sh

# rm -rf dist/*
# rm -f .buildozer

if [ -z "$WWW_DIR" ] ; then
    WWW_DIR=/opt/electrum-web
fi

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
fi


VERSION=`python3 -c "import electrum; print(electrum.version.ELECTRUM_VERSION)"`
info "VERSION: $VERSION"
REV=`git describe --tags`
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
apk1="Electrum-$VERSION.0-armeabi-v7a-release.apk"
apk1_unsigned="Electrum-$VERSION.0-armeabi-v7a-release-unsigned.apk"
apk2="Electrum-$VERSION.0-arm64-v8a-release.apk"
apk2_unsigned="Electrum-$VERSION.0-arm64-v8a-release-unsigned.apk"
if test -f "dist/$apk1"; then
    info "file exists: $apk1"
else
    if [ ! -z "$RELEASEMANAGER" ] ; then
        ./contrib/android/build.sh kivy all release
    else
        ./contrib/android/build.sh kivy all release-unsigned
        mv "dist/$apk1_unsigned" "dist/$apk1"
        mv "dist/$apk2_unsigned" "dist/$apk2"
    fi
fi

# the macos binary is built on a separate machine.
# the file that needs to be copied over is the codesigned release binary (regardless of builder role)
dmg=electrum-$VERSION.dmg
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

if [ "$answer" != "y" ] ;then
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
    test -f "$tarball"  || fail "tarball not found among sftp downloads"
    test -f "$appimage" || fail "appimage not found among sftp downloads"
    test -f "$win1"     || fail "win1 not found among sftp downloads"
    test -f "$win2"     || fail "win2 not found among sftp downloads"
    test -f "$win3"     || fail "win3 not found among sftp downloads"
    test -f "$apk1"     || fail "apk1 not found among sftp downloads"
    test -f "$apk2"     || fail "apk2 not found among sftp downloads"
    test -f "$dmg"      || fail "dmg not found among sftp downloads"
    test -f "$PROJECT_ROOT/dist/$tarball"    || fail "tarball not found among built files"
    test -f "$PROJECT_ROOT/dist/$appimage"   || fail "appimage not found among built files"
    test -f "$CONTRIB/build-wine/dist/$win1" || fail "win1 not found among built files"
    test -f "$CONTRIB/build-wine/dist/$win2" || fail "win2 not found among built files"
    test -f "$CONTRIB/build-wine/dist/$win3" || fail "win3 not found among built files"
    test -f "$PROJECT_ROOT/dist/$apk1"       || fail "apk1 not found among built files"
    test -f "$PROJECT_ROOT/dist/$apk2"       || fail "apk2 not found among built files"
    test -f "$PROJECT_ROOT/dist/$dmg"        || fail "dmg not found among built files"
    # compare downloaded binaries against ones we built
    cmp --silent "$tarball" "$PROJECT_ROOT/dist/$tarball" || fail "files are different. tarball."
    cmp --silent "$appimage" "$PROJECT_ROOT/dist/$appimage" || fail "files are different. appimage."
    rm -rf "$CONTRIB/build-wine/signed/" && mkdir --parents "$CONTRIB/build-wine/signed/"
    cp -f "$win1" "$win2" "$win3" "$CONTRIB/build-wine/signed/"
    "$CONTRIB/build-wine/unsign.sh" || fail "files are different. windows."
    "$CONTRIB/android/apkdiff.py" "$apk1" "$PROJECT_ROOT/dist/$apk1" || fail "files are different. android."
    "$CONTRIB/android/apkdiff.py" "$apk2" "$PROJECT_ROOT/dist/$apk2" || fail "files are different. android."
    cmp --silent "$dmg" "$PROJECT_ROOT/dist/$dmg" || fail "files are different. macos."
    # all files matched. sign them.
    rm -rf "$PROJECT_ROOT/dist/sigs/"
    mkdir --parents "$PROJECT_ROOT/dist/sigs/"
    for fname in "$tarball" "$appimage" "$win1" "$win2" "$win3" "$apk1" "$apk2" "$dmg" ; do
        signame="$fname.$GPGUSER.asc"
        gpg --sign --armor --detach $PUBKEY --output "$PROJECT_ROOT/dist/sigs/$signame" "$fname"
    done
    # upload sigs
    ELECBUILD_UPLOADFROM="$PROJECT_ROOT/dist/sigs/" "$CONTRIB/upload"

else
    # ONLY release manager

    cd "$PROJECT_ROOT"

    info "updating www repo"
    ./contrib/make_download $WWW_DIR
    info "signing the version announcement file"
    sig=`./run_electrum -o signmessage $ELECTRUM_SIGNING_ADDRESS $VERSION -w $ELECTRUM_SIGNING_WALLET`
    echo "{ \"version\":\"$VERSION\", \"signatures\":{ \"$ELECTRUM_SIGNING_ADDRESS\":\"$sig\"}}" > $WWW_DIR/version


    if [ $REV != $VERSION ]; then
        fail "versions differ, not uploading"
    fi

    # upload the files
    if test -f dist/uploaded; then
        info "files already uploaded"
    else
        ./contrib/upload
        touch dist/uploaded
    fi

    # push changes to website repo
    pushd $WWW_DIR
    git diff
    git commit -a -m "version $VERSION"
    git push
    popd
fi


info "release.sh finished successfully."
info "now you should run WWW_DIR/publish.sh to sign the website commit and upload signature"
