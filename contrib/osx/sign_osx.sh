#!/usr/bin/env bash

set -e

security -v unlock-keychain login.keychain


PACKAGE=Electrum


. "$(dirname "$0")/../build_tools_util.sh"


CONTRIB_OSX="$(dirname "$(realpath "$0")")"
CONTRIB="$CONTRIB_OSX/.."
PROJECT_ROOT="$CONTRIB/.."
CACHEDIR="$CONTRIB_OSX/.cache"


cd "$PROJECT_ROOT"


# Code Signing: See https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html
if [ -n "$CODESIGN_CERT" ]; then
    # Test the identity is valid for signing by doing this hack. There is no other way to do this.
    cp -f /bin/ls ./CODESIGN_TEST
    set +e
    codesign -s "$CODESIGN_CERT" --dryrun -f ./CODESIGN_TEST > /dev/null 2>&1
    res=$?
    set -e
    rm -f ./CODESIGN_TEST
    if ((res)); then
        fail "Code signing identity \"$CODESIGN_CERT\" appears to be invalid."
    fi
    unset res
    info "Code signing enabled using identity \"$CODESIGN_CERT\""
else
    fail "Code signing DISABLED. Specify a valid macOS Developer identity installed on the system to enable signing."
fi


function DoCodeSignMaybe { # ARGS: infoName fileOrDirName
    infoName="$1"
    file="$2"
    deep=""
    if [ -z "$CODESIGN_CERT" ]; then
        # no cert -> we won't codesign
        return
    fi
    if [ -d "$file" ]; then
        deep="--deep"
    fi
    if [ -z "$infoName" ] || [ -z "$file" ] || [ ! -e "$file" ]; then
        fail "Argument error to internal function DoCodeSignMaybe()"
    fi
    hardened_arg="--entitlements=${CONTRIB_OSX}/entitlements.plist -o runtime"

    info "Code signing ${infoName}..."
    codesign -f -v $deep -s "$CODESIGN_CERT" $hardened_arg "$file" || fail "Could not code sign ${infoName}"
}

VERSION=$(git describe --tags --dirty --always)

DoCodeSignMaybe "app bundle" "dist/${PACKAGE}.app"

if [ ! -z "$CODESIGN_CERT" ]; then
    if [ ! -z "$APPLE_ID_USER" ]; then
        info "Notarizing .app with Apple's central server..."
        "${CONTRIB_OSX}/notarize_app.sh" "dist/${PACKAGE}.app" || fail "Could not notarize binary."
    else
        warn "AppleID details not set! Skipping Apple notarization."
    fi
fi

info "Creating .DMG"
hdiutil create -fs HFS+ -volname $PACKAGE -srcfolder dist/$PACKAGE.app dist/electrum-$VERSION.dmg || fail "Could not create .DMG"

DoCodeSignMaybe ".DMG" "dist/electrum-${VERSION}.dmg"
