#!/usr/bin/env bash

# Set a fixed umask as this leaks into docker containers
umask 0022

RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color
function info {
    printf "\r💬 ${BLUE}INFO:${NC}  ${1}\n"
}
function fail {
    printf "\r🗯 ${RED}ERROR:${NC} ${1}\n"
    exit 1
}
function warn {
    printf "\r⚠️  ${YELLOW}WARNING:${NC}  ${1}\n"
}


# based on https://superuser.com/questions/497940/script-to-verify-a-signature-with-gpg
function verify_signature() {
    local file=$1 keyring=$2 out=
    if out=$(gpg --no-default-keyring --keyring "$keyring" --status-fd 1 --verify "$file" 2>/dev/null) &&
        echo "$out" | grep -qs "^\[GNUPG:\] VALIDSIG "; then
        return 0
    else
        echo "$out" >&2
        exit 1
    fi
}

function verify_hash() {
    local file=$1 expected_hash=$2
    actual_hash=$(sha256sum $file | awk '{print $1}')
    if [ "$actual_hash" == "$expected_hash" ]; then
        return 0
    else
        echo "$file $actual_hash (unexpected hash)" >&2
        rm "$file"
        exit 1
    fi
}

function download_if_not_exist() {
    local file_name=$1 url=$2
    if [ ! -e $file_name ] ; then
        wget -O $file_name "$url"
    fi
}

# https://github.com/travis-ci/travis-build/blob/master/lib/travis/build/templates/header.sh
function retry() {
    local result=0
    local count=1
    while [ $count -le 3 ]; do
        [ $result -ne 0 ] && {
            echo -e "\nThe command \"$@\" failed. Retrying, $count of 3.\n" >&2
        }
        ! { "$@"; result=$?; }
        [ $result -eq 0 ] && break
        count=$(($count + 1))
        sleep 1
    done

    [ $count -gt 3 ] && {
        echo -e "\nThe command \"$@\" failed 3 times.\n" >&2
    }

    return $result
}

function gcc_with_triplet()
{
    TRIPLET="$1"
    CMD="$2"
    shift 2
    if [ -n "$TRIPLET" ] ; then
        "$TRIPLET-$CMD" "$@"
    else
        "$CMD" "$@"
    fi
}

function gcc_host()
{
    gcc_with_triplet "$GCC_TRIPLET_HOST" "$@"
}

function gcc_build()
{
    gcc_with_triplet "$GCC_TRIPLET_BUILD" "$@"
}

function host_strip()
{
    if [ "$GCC_STRIP_BINARIES" -ne "0" ] ; then
        case "$BUILD_TYPE" in
            linux|wine)
                gcc_host strip "$@"
                ;;
            darwin)
                # TODO: Strip on macOS?
                ;;
        esac
    fi
}

# on MacOS, there is no realpath by default
if ! [ -x "$(command -v realpath)" ]; then
    function realpath() {
        [[ $1 = /* ]] && echo "$1" || echo "$PWD/${1#./}"
    }
fi


export SOURCE_DATE_EPOCH=1530212462
export ZERO_AR_DATE=1 # for macOS
export PYTHONHASHSEED=22
# Set the build type, overridden by wine build
export BUILD_TYPE="${BUILD_TYPE:-$(uname | tr '[:upper:]' '[:lower:]')}"
# Add host / build flags if the triplets are set
if [ -n "$GCC_TRIPLET_HOST" ] ; then
    export AUTOCONF_FLAGS="$AUTOCONF_FLAGS --host=$GCC_TRIPLET_HOST"
fi
if [ -n "$GCC_TRIPLET_BUILD" ] ; then
    export AUTOCONF_FLAGS="$AUTOCONF_FLAGS --build=$GCC_TRIPLET_BUILD"
fi

export GCC_STRIP_BINARIES="${GCC_STRIP_BINARIES:-0}"

if [ -n "$CIRRUS_CPU" ] ; then
    # special-case for CI. see https://github.com/cirruslabs/cirrus-ci-docs/issues/1115
    export CPU_COUNT="$CIRRUS_CPU"
else
    export CPU_COUNT="$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
fi
info "Found $CPU_COUNT CPUs, which we might use for building."


function break_legacy_easy_install() {
    # We don't want setuptools sneakily installing dependencies, invisible to pip.
    # This ensures that if setuptools calls distutils which then calls easy_install,
    # easy_install will not download packages over the network.
    # see https://pip.pypa.io/en/stable/reference/pip_install/#controlling-setup-requires
    # see https://github.com/pypa/setuptools/issues/1916#issuecomment-743350566
    info "Intentionally breaking legacy easy_install."
    DISTUTILS_CFG="${HOME}/.pydistutils.cfg"
    DISTUTILS_CFG_BAK="${HOME}/.pydistutils.cfg.orig"
    # If we are not inside docker, we might be overwriting a config file on the user's system...
    if [ -e "$DISTUTILS_CFG" ] && [ ! -e "$DISTUTILS_CFG_BAK" ]; then
        warn "Overwriting python distutils config file at '$DISTUTILS_CFG'. A copy will be saved at '$DISTUTILS_CFG_BAK'."
        mv "$DISTUTILS_CFG" "$DISTUTILS_CFG_BAK"
    fi
    cat <<EOF > "$DISTUTILS_CFG"
[easy_install]
index_url = ''
find_links = ''
EOF
}

