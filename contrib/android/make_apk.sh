#!/bin/bash

set -e

CONTRIB_ANDROID="$(dirname "$(readlink -e "$0")")"
CONTRIB="$CONTRIB_ANDROID"/..
PROJECT_ROOT="$CONTRIB"/..
PACKAGES="$PROJECT_ROOT"/packages/
LOCALE="$PROJECT_ROOT"/electrum/locale/

. "$CONTRIB"/build_tools_util.sh


# arguments have been checked in build.sh
export ELEC_APK_GUI=$1

if [ ! -d "$PACKAGES" ]; then
    "$CONTRIB"/make_packages.sh || fail "make_packages failed"
fi

pushd "$PROJECT_ROOT"
git submodule update --init
popd

# update locale
info "preparing electrum-locale."
(
    LOCALE="$PROJECT_ROOT/electrum/locale/"
    # we want the binary to have only compiled (.mo) locale files; not source (.po) files
    rm -rf "$LOCALE"
    "$CONTRIB/build_locale.sh" "$CONTRIB/deterministic-build/electrum-locale/locale/" "$LOCALE"
)

pushd "$CONTRIB_ANDROID"

info "apk building phase starts."

# Uncomment and change below to set a custom android package id,
# e.g. to allow simultaneous mainnet and testnet installs of the apk.
# defaults:
#   export APP_PACKAGE_NAME=Electrum
#   export APP_PACKAGE_DOMAIN=org.electrum
# FIXME: changing "APP_PACKAGE_NAME" seems to require a clean rebuild of ".buildozer/",
#        to avoid that, maybe change "APP_PACKAGE_DOMAIN" instead.
# So, in particular, to build a testnet apk, simply uncomment:
#export APP_PACKAGE_DOMAIN=org.electrum.testnet

if [ ! $CI ]; then
    # override log level specified in buildozer.spec to "debug":
    export BUILDOZER_LOG_LEVEL=2
fi

if [[ "$3" == "release" ]] ; then
    # do release build, and sign the APKs.
    TARGET="release"
    export P4A_RELEASE_KEYSTORE_PASSWD="$4"
    export P4A_RELEASE_KEYALIAS_PASSWD="$4"
    export P4A_RELEASE_KEYSTORE=~/.keystore
    export P4A_RELEASE_KEYALIAS=electrum
    if [ -z "$P4A_RELEASE_KEYSTORE_PASSWD" ] || [ -z "$P4A_RELEASE_KEYALIAS_PASSWD" ]; then
        echo "p4a password not defined"
        exit 1
    fi
elif [[ "$3" == "release-unsigned" ]] ; then
    # do release build, but do not sign the APKs.
    TARGET="release"
elif [[ "$3" == "debug" ]] ; then
    # do debug build.
    TARGET="apk"
    export P4A_DEBUG_KEYSTORE="$CONTRIB_ANDROID"/android_debug.keystore
    export P4A_DEBUG_KEYSTORE_PASSWD=unsafepassword
    export P4A_DEBUG_KEYALIAS_PASSWD=unsafepassword
    export P4A_DEBUG_KEYALIAS=electrum
    # create keystore if needed
    if [ ! -f "$P4A_DEBUG_KEYSTORE" ]; then
        keytool -genkey -v -keystore "$CONTRIB_ANDROID"/android_debug.keystore \
            -alias "$P4A_DEBUG_KEYALIAS" -keyalg RSA -keysize 2048 -validity 10000 \
            -dname "CN=mqttserver.ibm.com, OU=ID, O=IBM, L=Hursley, S=Hants, C=GB" \
            -storepass "$P4A_DEBUG_KEYSTORE_PASSWD" \
            -keypass "$P4A_DEBUG_KEYALIAS_PASSWD"
    fi
    export ELEC_APK_USE_CURRENT_TIME=1
else
    fail "unknown build type"
fi


if [[ "$2" == "all" ]] ; then
    # build all apks
    export APP_ANDROID_ARCH=armeabi-v7a
    make $TARGET
    export APP_ANDROID_ARCH=arm64-v8a
    make $TARGET
    #export APP_ANDROID_ARCH=x86
    #make $TARGET
else
    export APP_ANDROID_ARCH=$2
    make $TARGET
fi

popd


info "done."
ls -la "$PROJECT_ROOT/dist"
sha256sum "$PROJECT_ROOT/dist"/*
