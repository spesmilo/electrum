#!/bin/bash
#
# env vars:
# - WWW_DIR: path to "electrum-web" git clone
# - for signing the version announcement file:
#   - ELECTRUM_SIGNING_ADDRESS (required)
#   - ELECTRUM_SIGNING_WALLET (required)
#

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/.."
CONTRIB="$PROJECT_ROOT/contrib"

cd "$PROJECT_ROOT"

. "$CONTRIB"/build_tools_util.sh


echo -n "Remember to run add_cosigner to add any additional sigs.  Continue (y/n)? "
read answer
if [ "$answer" != "y" ]; then
    echo "exit"
    exit 1
fi


if [ -z "$WWW_DIR" ] ; then
    WWW_DIR=/opt/electrum-web
fi

if [ -z "$ELECTRUM_SIGNING_WALLET" ] || [ -z "$ELECTRUM_SIGNING_ADDRESS" ]; then
    echo "You need to set env vars ELECTRUM_SIGNING_WALLET and ELECTRUM_SIGNING_ADDRESS!"
    exit 1
fi

# get previous versions from WWW_DIR
VERSION_STABLE=$(jq -r '.version' "$WWW_DIR/version")
PREVIOUS_STABLE_VERSION=$VERSION_STABLE
# returns version 0.0 if previous alpha or beta is not found
VERSION_ALPHA=$(jq -r '.extradata.version_alpha // "0.0"' "$WWW_DIR/version")
VERSION_BETA=$(jq -r '.extradata.version_beta // "0.0"' "$WWW_DIR/version")
if [ "$VERSION_STABLE" == null ]; then
    echo "Couldn't find previous version in $WWW_DIR/version"
    exit 1
fi

# get current electrum version from electrum/version.py
RELEASE_VERSION=$("$CONTRIB"/print_electrum_version.py)
if [[ "$RELEASE_VERSION" =~ [a] ]]; then
    VERSION_ALPHA=$RELEASE_VERSION
elif [[ "$RELEASE_VERSION" =~ [b] ]]; then
    VERSION_BETA=$RELEASE_VERSION
else
    VERSION_STABLE=$RELEASE_VERSION
fi
info "RELEASE_VERSION: $RELEASE_VERSION"

# keep the android versioncode for the stable release version or generate new if RELEASE_VERSION is stable
if [[ "$VERSION_STABLE" != "$PREVIOUS_STABLE_VERSION" ]]; then
    ANDROID_VERSIONCODE_NULLARCH=$("$CONTRIB"/android/get_apk_versioncode.py "null")
    info "ANDROID_VERSIONCODE_NULLARCH: $ANDROID_VERSIONCODE_NULLARCH"
else
    ANDROID_VERSIONCODE_NULLARCH=$(jq -r '.extradata.android_versioncode_nullarch' "$WWW_DIR/version")
    info "reusing old android versioncode for unstable release: $ANDROID_VERSIONCODE_NULLARCH"
fi
# ^ note: should parse as an integer in the final json

if [ "$ANDROID_VERSIONCODE_NULLARCH" == null ]; then
    echo "No valid ANDROID_VERSIONCODE_NULLARCH: $ANDROID_VERSIONCODE_NULLARCH"
    exit 1
fi

set -x

info "updating www repo in $WWW_DIR"
./contrib/make_download "$WWW_DIR"

info "signing the stable version field"
version_sig=$(./run_electrum -o signmessage "$ELECTRUM_SIGNING_ADDRESS" "$VERSION_STABLE" -w "$ELECTRUM_SIGNING_WALLET")

# serialize extradata msg using the same method as in update_checker.py to prevent differences
extradata=$(python3 -c "import json, sys; print(json.dumps({
    'android_versioncode_nullarch': int(sys.argv[1]),
    'version_alpha': sys.argv[2],
    'version_beta': sys.argv[3]
}, sort_keys=True, separators=(',', ':')))" "$ANDROID_VERSIONCODE_NULLARCH" "$VERSION_ALPHA" "$VERSION_BETA")

# signing the hash of extradata instead of passing extradata directly,
# so it doesn't get parsed as dict when passing it into signmessage,
# so the resulting sig is on a double sha256 of extradata
extradata_hash=$(echo -n "$extradata" | sha256sum | awk '{print $1}')
info "signing the extradata fields hash, extradata=$extradata extradata_hash=$extradata_hash"
extradata_hash_sig=$(./run_electrum -o signmessage "$ELECTRUM_SIGNING_ADDRESS" "$extradata_hash" -w "$ELECTRUM_SIGNING_WALLET")

cat <<EOF > "$WWW_DIR"/version
{
    "version": "$VERSION_STABLE",
    "signatures": {"$ELECTRUM_SIGNING_ADDRESS": "$version_sig"},
    "extradata": $extradata,
    "extradata_hash_signatures": {"$ELECTRUM_SIGNING_ADDRESS": "$extradata_hash_sig"}
}
EOF

# push changes to website repo
pushd "$WWW_DIR"
git diff
git commit -a -m "version $VERSION"
git push
popd


info "release_www.sh finished successfully."
info "now you should run WWW_DIR/publish.sh to sign the website commit and upload signature"
