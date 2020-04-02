#!/usr/bin/env bash

cdrkit_version=1.1.11
cdrkit_download_path=http://distro.ibiblio.org/fatdog/source/600/c
cdrkit_file_name=cdrkit-${cdrkit_version}.tar.bz2
cdrkit_sha256_hash=b50d64c214a65b1a79afe3a964c691931a4233e2ba605d793eb85d0ac3652564
cdrkit_patches=cdrkit-deterministic.patch
genisoimage=genisoimage-$cdrkit_version

libdmg_url=https://github.com/theuni/libdmg-hfsplus


export LD_PRELOAD=$(locate libfaketime.so.1)
export FAKETIME="2000-01-22 00:00:00"
export PATH=$PATH:~/bin

. $(dirname "$0")/base.sh

if [ -z "$1" ]; then
    echo "Usage: $0 ElectrumSys.app"
    exit -127
fi

mkdir -p ~/bin

if ! which ${genisoimage} > /dev/null 2>&1; then
	mkdir -p /tmp/electrumsys-macos
	cd /tmp/electrumsys-macos
	info "Downloading cdrkit $cdrkit_version"
	wget -nc ${cdrkit_download_path}/${cdrkit_file_name}
	tar xvf ${cdrkit_file_name}

	info "Patching genisoimage"
	cd cdrkit-${cdrkit_version}
	patch -p1 < ../cdrkit-deterministic.patch

	info "Building genisoimage"
	cmake . -Wno-dev
	make genisoimage
	cp genisoimage/genisoimage ~/bin/${genisoimage}
fi

if ! which dmg > /dev/null 2>&1; then
    mkdir -p /tmp/electrumsys-macos
	cd /tmp/electrumsys-macos
	info "Downloading libdmg"
    LD_PRELOAD= git clone ${libdmg_url}
    cd libdmg-hfsplus
    info "Building libdmg"
    cmake .
    make
    cp dmg/dmg ~/bin
fi

${genisoimage} -version || fail "Unable to install genisoimage"
dmg -|| fail "Unable to install libdmg"

plist=$1/Contents/Info.plist
test -f "$plist" || fail "Info.plist not found"
VERSION=$(grep -1 ShortVersionString $plist |tail -1|gawk 'match($0, /<string>(.*)<\/string>/, a) {print a[1]}')
echo $VERSION

rm -rf /tmp/electrumsys-macos/image > /dev/null 2>&1
mkdir /tmp/electrumsys-macos/image/
cp -r $1 /tmp/electrumsys-macos/image/

build_dir=$(dirname "$1")
test -n "$build_dir" -a -d "$build_dir" || exit
cd $build_dir

${genisoimage} \
    -no-cache-inodes \
    -D \
    -l \
    -probe \
    -V "ElectrumSys" \
    -no-pad \
    -r \
    -dir-mode 0755 \
    -apple \
    -o ElectrumSys_uncompressed.dmg \
    /tmp/electrumsys-macos/image || fail "Unable to create uncompressed dmg"

dmg dmg ElectrumSys_uncompressed.dmg electrumsys-$VERSION.dmg || fail "Unable to create compressed dmg"
rm ElectrumSys_uncompressed.dmg

echo "Done."
sha256sum electrumsys-$VERSION.dmg
