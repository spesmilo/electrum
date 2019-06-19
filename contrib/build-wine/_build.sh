#!/bin/bash

here=$(dirname "$0")
test -n "$here" -a -d "$here" || (echo "Cannot determine build dir. FIXME!" && exit 1)
pushd "$here"
here=`pwd`  # get an absolute path
popd
. "$here"/../base.sh # functions we use below (fail, et al)

if [ ! -z "$1" ]; then
    to_build="$1"
else
    fail "Please specify a release tag or branch to build (eg: master or 4.0.0, etc)"
fi

set -e

git checkout "$to_build" || fail "Could not branch or tag $to_build"

GIT_COMMIT_HASH=$(git rev-parse HEAD)

info "Clearing $here/build and $here/dist..."
rm "$here"/build/* -fr
rm "$here"/dist/* -fr

rm -fr /tmp/electrum-build
mkdir -p /tmp/electrum-build

info "Refreshing submodules..."
git submodule init
git submodule update

build_secp256k1() {
    info "Building libsecp256k1..."
    (
        set -e
        build_dll() {
            #sudo apt-get install -y mingw-w64
            export SOURCE_DATE_EPOCH=1530212462
            echo "libsecp256k1_la_LDFLAGS = -no-undefined" >> Makefile.am
            echo "LDFLAGS = -no-undefined" >> Makefile.am
            ./autogen.sh || fail "Could not run autogen.sh for secp256k1"
            # Note: always set --host along with --build.
            LDFLAGS="-Wl,--no-insert-timestamp -Wl,-no-undefined -Wl,--no-undefined" ./configure \
                --host=$1 \
                --build=x86_64-pc-linux-gnu \
                --enable-module-recovery \
                --enable-experimental \
                --enable-module-ecdh \
                --disable-jni \
                --with-bignum=no \
                --enable-module-schnorr \
                --disable-tests \
                --disable-static \
                --enable-shared || fail "Could not run ./configure for secp256k1"
            make LDFLAGS='-no-undefined' -j4 || fail "Could not build secp256k1"
            ${1}-strip .libs/libsecp256k1-0.dll
        }

        pushd "$here"/../secp256k1 || fail "Could not chdir to secp256k1"
        LIBSECP_VERSION="a9752bb2d1c1f5abb30e5bde7a1fad582629e46d"  # According to Mark B. Lundeberg, using a commit hash guarantees no repository man-in-the-middle funny business as git is secure when verifying hashes.
        git checkout $LIBSECP_VERSION || fail "Could not check out secp256k1 $LIBSECP_VERSION"
        git clean -f -x -q

        build_dll i686-w64-mingw32  # 64-bit would be: x86_64-w64-mingw32
        mv .libs/libsecp256k1-0.dll libsecp256k1.dll || fail "Could not find generated DLL"

        find -exec touch -d '2000-11-11T11:11:11+00:00' {} +

        popd
    ) || fail "Could not build libsecp256k1"
    info "Build of libsecp256k1 finished"
}
build_secp256k1

build_zbar() {
    info "Building libzbar..."
    (
        set -e
        build_dll() {
            export SOURCE_DATE_EPOCH=1530212462
            echo "libzbar_la_LDFLAGS += -Wc,-static" >> zbar/Makefile.am
            echo "LDFLAGS += -Wc,-static" >> Makefile.am
            autoreconf -vfi || fail "Could not run autoreconf for zbar"
            # Note: It's really important that you set --build and --host when running configure
            # Otherwise weird voodoo magic happens with Docker and Wine. Also for correctness GNU
            # autoconf docs say you should.
            # https://www.gnu.org/software/autoconf/manual/autoconf-2.69/html_node/Hosts-and-Cross_002dCompilation.html
            LDFLAGS="-Wl,--no-insert-timestamp" ./configure \
                --host=$1 \
                --build=x86_64-pc-linux-gnu \
                --with-x=no \
                --enable-pthread=no \
                --enable-doc=no \
                --enable-video=no \
                --with-directshow=no \
                --with-jpeg=no \
                --with-python=no \
                --with-gtk=no \
                --with-qt=no \
                --with-java=no \
                --with-imagemagick=no \
                --with-dbus=no \
                --enable-codes=qrcode \
                --disable-dependency-tracking \
                --disable-static \
                --enable-shared || fail "Could not run ./configure for zbar"
            make -j4 || fail "Could not build zbar"
            ${1}-strip zbar/.libs/libzbar-0.dll
        }

        pushd "$here"/../zbar || fail "Could not chdir to zbar"
        LIBZBAR_VERSION="1d51925e6cc9151f4a73781989f21fcd7b57ef32" # version 0.23
        git checkout $LIBZBAR_VERSION || fail "Could not check out zbar $LIBZBAR_VERSION"
        git clean -f -x -q

        build_dll i686-w64-mingw32 # 64-bit would be: x86_64-w64-mingw32
        mv zbar/.libs/libzbar-0.dll libzbar-0.dll || fail "Could not find generated DLL"

        find -exec touch -d '2000-11-11T11:11:11+00:00' {} +

        popd
    ) || fail "Could not build libzbar"
    info "Build of libzbar finished"
}
build_zbar

prepare_wine() {
    info "Preparing Wine..."
    (
        set -e
        pushd "$here"
        here=`pwd`
        # Please update these carefully, some versions won't work under Wine
        NSIS_URL='https://github.com/cculianu/Electron-Cash-Build-Tools/releases/download/v1.0/nsis-3.02.1-setup.exe'
        NSIS_SHA256=736c9062a02e297e335f82252e648a883171c98e0d5120439f538c81d429552e

        LIBUSB_URL='https://github.com/cculianu/Electron-Cash-Build-Tools/releases/download/v1.0/libusb-1.0.21.7z'
        LIBUSB_SHA256=acdde63a40b1477898aee6153f9d91d1a2e8a5d93f832ca8ab876498f3a6d2b8

        PYINSTALLER_REPO='https://github.com/EchterAgo/pyinstaller.git'
        PYINSTALLER_COMMIT=d1cdd726d6a9edc70150d5302453fb90fdd09bf2

        ## These settings probably don't need change
        export WINEPREFIX=/opt/wine64
        #export WINEARCH='win32'

        PYHOME=c:/python$PYTHON_VERSION  # NB: PYTON_VERSION comes from ../base.sh
        PYTHON="wine $PYHOME/python.exe -OO -B"

        # Clean up Wine environment. Breaks docker so leave this commented-out.
        #echo "Cleaning $WINEPREFIX"
        #rm -rf $WINEPREFIX
        #echo "done"

        wine 'wineboot'

        info "Cleaning tmp"
        rm -rf tmp
        mkdir -p tmp
        info "done"

        cd tmp

        #NB: Use NOPGP=1 env var to skip this verify pgp keys stuff (for developer testing without having to wait)
        if [ -z "$NOPGP" ]; then
            # note: you might need "sudo apt-get install dirmngr" for the following
            # keys from https://www.python.org/downloads/#pubkeys
            info "Downloading Python dev keyring (may take a few minutes)..."
            KEYRING_PYTHON_DEV=keyring-electroncash-build-python-dev.gpg
            KEY_SERVERS="keyserver.ubuntu.com keyserver.pgp.com pgp.mit.edu"
            got1=""
            # Try a bunch of PGP servers. The fastest one is usually the ubuntu one...
            for key_server in $KEY_SERVERS; do
                info "Downloading from ${key_server}..."
                gpg -v --no-default-keyring --keyring $KEYRING_PYTHON_DEV --keyserver $key_server --recv-keys 531F072D39700991925FED0C0EDDC5F26A45C816 26DEA9D4613391EF3E25C9FF0A5B101836580288 CBC547978A3964D14B9AB36A6AF053F07D9DC8D2 C01E1CAD5EA2C4F0B8E3571504C367C218ADD4FF 12EF3DC38047DA382D18A5B999CDEA9DA4135B38 8417157EDBE73D9EAC1E539B126EB563A74B06BF DBBF2EEBF925FAADCF1F3FFFD9866941EA5BBD71 2BA0DB82515BBB9EFFAC71C5C9BE28DEE6DF025C 0D96DF4D4110E5C43FBFB17F2D347EA6AA65421D C9B104B3DD3AA72D7CCB1066FB9921286F5E1540 97FC712E4C024BBEA48A61ED3A5CA953F73C700D 7ED10B6531D7C8E1BC296021FC624643487034E5 && got1=1 && break
            done
            if [ -z "$got1" ]; then
                fail "Failed to download PGP keys."
            fi
        fi

        info "Installing Python ..."
        # Install Python
        for msifile in core dev exe lib pip tools; do
            info "Installing $msifile..."
            wget "https://www.python.org/ftp/python/$PYTHON_VERSION/win32/${msifile}.msi"
            wget "https://www.python.org/ftp/python/$PYTHON_VERSION/win32/${msifile}.msi.asc"
            [ -z "$NOPGP" ] && verify_signature "${msifile}.msi.asc" $KEYRING_PYTHON_DEV
            wine msiexec /i "${msifile}.msi" /qb TARGETDIR=C:/python$PYTHON_VERSION || fail "Failed to install Python component: ${msifile}"
        done

        info "Upgrading pip ..."
        # upgrade pip
        $PYTHON -m pip install pip --upgrade

        # The below requirements-wine-build.txt uses hashed packages that we
        # need for pyinstaller and other parts of the build.  Using a hashed
        # requirements file hardens the build against dependency attacks.
        info "Installing build requirements from requirements-wine-build.txt ..."
        $PYTHON -m pip install -I -r $here/requirements-wine-build.txt || fail "Failed to install build requirements"

        info "Compiling PyInstaller bootloader with AntiVirus False-Positive Protection™ ..."
        git clone $PYINSTALLER_REPO
        (
            cd pyinstaller
            git checkout -b pinned $PYINSTALLER_COMMIT
            rm -fv PyInstaller/bootloader/Windows-*/run*.exe || true  # Make sure EXEs that came with repo are deleted -- we rebuild them and need to detect if build failed
            echo "const char *ec_tag = \"tagged by Electron-Cash@$GIT_COMMIT_HASH\";" >> ./bootloader/src/pyi_main.c
            pushd bootloader
            # If switching to 64-bit Windows, edit CC= below
            python3 ./waf all CC=i686-w64-mingw32-gcc CFLAGS="-Wno-stringop-overflow -static"
            # Note: it's possible for the EXE to not be there if the build
            # failed but didn't return exit status != 0 to the shell (waf bug?);
            # So we need to do this to make sure the EXE is actually there.
            # If we switch to 64-bit, edit this path below.
            popd
            [ -e PyInstaller/bootloader/Windows-32bit/runw.exe ] || fail "Could not find runw.exe in target dir!"
        ) || fail "PyInstaller bootloader build failed"
        info "Installing PyInstaller ..."
        $PYTHON -m pip install ./pyinstaller || fail "PyInstaller install failed"

        wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" -v || fail "Pyinstaller installed but cannot be run."

        info "Installing Packages from requirements-binaries ..."
        $PYTHON -m pip install -r ../../deterministic-build/requirements-binaries.txt || fail "Failed to install requirements-binaries"

        info "Installing NSIS ..."
        # Install NSIS installer
        wget -O nsis.exe "$NSIS_URL"
        verify_hash nsis.exe $NSIS_SHA256
        wine nsis.exe /S || fail "Could not run nsis"

        info "Installing libusb ..."
        wget -O libusb.7z "$LIBUSB_URL"
        verify_hash libusb.7z "$LIBUSB_SHA256"
        7z x -olibusb libusb.7z
        mkdir -p $WINEPREFIX/drive_c/tmp
        cp libusb/MS32/dll/libusb-1.0.dll $WINEPREFIX/drive_c/tmp/ || fail "Could not copy libusb.dll to its destination"

        # libsecp256k1 & libzbar
        mkdir -p $WINEPREFIX/drive_c/tmp
        cp "$here"/../secp256k1/libsecp256k1.dll $WINEPREFIX/drive_c/tmp/ || fail "Could not copy libsecp to its destination"
        cp "$here"/../zbar/libzbar-0.dll $WINEPREFIX/drive_c/tmp/ || fail "Could not copy libzbar to its destination"


        info "Copying DLLs needed by Pyinstaller ..."
        # add dlls needed for pyinstaller:
        cp $WINEPREFIX/drive_c/python$PYTHON_VERSION/Lib/site-packages/PyQt5/Qt/bin/* $WINEPREFIX/drive_c/python$PYTHON_VERSION/

        popd

    ) || fail "Could not prepare Wine"
    info "Wine is configured."
}
prepare_wine

info "Resetting modification time in C:\Python..."
# (Because of some bugs in pyinstaller)
pushd /opt/wine64/drive_c/python*
find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd
ls -l /opt/wine64/drive_c/python*

build_the_app() {
    info "Building $PACKAGE ..."
    (
        set -e

        pushd "$here"
        here=`pwd`

        NAME_ROOT=$PACKAGE  # PACKAGE comes from ../base.sh
        # These settings probably don't need any change
        export WINEPREFIX=/opt/wine64
        export PYTHONDONTWRITEBYTECODE=1

        PYHOME=c:/python$PYTHON_VERSION
        PYTHON="wine $PYHOME/python.exe -OO -B"

        pushd "$here"/../electrum-locale
        for i in ./locale/*; do
            dir=$i/LC_MESSAGES
            mkdir -p $dir
            msgfmt --output-file=$dir/electron-cash.mo $i/electron-cash.po || true
        done
        popd


        pushd "$here"/../..  # go to top level


        VERSION=`git describe --tags`
        info "Version to release: $VERSION"
        info "Fudging timestamps on all files for determinism ..."
        find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
        popd  # go back to $here

        cp "$here"/../../LICENCE "$here"/tmp
        cp -r "$here"/../electrum-locale/locale $WINEPREFIX/drive_c/electroncash/lib/

        # Install frozen dependencies
        info "Installing frozen dependencies ..."
        $PYTHON -m pip install -r "$here"/../deterministic-build/requirements.txt || fail "Failed to install requirements"
        $PYTHON -m pip install -r "$here"/../deterministic-build/requirements-hw.txt || fail "Failed to install requirements-hw"

        pushd $WINEPREFIX/drive_c/electroncash
        $PYTHON setup.py install || fail "Failed setup.py install"
        popd

        rm -rf dist/

        # build standalone and portable versions
        info "Running Pyinstaller to build standalone and portable .exe versions ..."
        wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" --noconfirm --ascii --name $NAME_ROOT-$VERSION -w deterministic.spec || fail "Pyinstaller failed"


        # set timestamps in dist, in order to make the installer reproducible
        pushd dist
        find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
        popd


        # build NSIS installer
        info "Running makensis to build setup .exe version ..."
        # $VERSION could be passed to the electron-cash.nsi script, but this would require some rewriting in the script iself.
        wine "$WINEPREFIX/drive_c/Program Files (x86)/NSIS/makensis.exe" /DPRODUCT_VERSION=$VERSION electron-cash.nsi || fail "makensis failed"

        cd dist
        mv $NAME_ROOT-setup.exe $NAME_ROOT-$VERSION-setup.exe  || fail "Failed to move $NAME_ROOT-$VERSION-setup.exe to the output dist/ directory"

        popd

    ) || fail "Failed to build $PACKAGE"
    info "Done building."
}
build_the_app
