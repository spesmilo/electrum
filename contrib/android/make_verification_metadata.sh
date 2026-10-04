#!/bin/bash
#
# Regenerate the gradle dependency verification metadata in verification-metadata/.
#
# Run this after anything that changes what the barcode scanner builds resolve: a gradle or
# AGP bump, a new/edited patch, a zxing-cpp/CameraView/BarcodeScannerView version bump, or a
# change to android.gradle_dependencies in buildozer_qml.spec. Then review and commit the
# resulting xml.
#
# Must run inside the builder container, the same way make_barcode_scanner.sh does:
#
#   ./contrib/android/build.sh qml all debug     # to get a container, or
#   docker run --rm -it -v "$PWD":/home/user/wspace/electrum \
#       --workdir /home/user/wspace/electrum electrum-android-builder-img \
#       ./contrib/android/make_verification_metadata.sh
#
# This drives make_barcode_scanner.sh itself rather than reimplementing it, so the metadata
# always describes exactly what the real build resolves, with the same patches and the same
# gradle invocations.
#
# Two things this handles that are easy to get wrong by hand:
#
#  - It uses a throwaway GRADLE_USER_HOME. Generating against a warm gradle cache silently
#    omits artifacts that are already present (parent poms and BOM descriptors such as
#    guava-parent and junit-bom), and the next clean build then fails verification on them.
#
#  - The zxing-cpp aar embeds jni/<abi>/libzxingcpp_android.so, so it has one legitimate
#    checksum per abi, while BarcodeScannerView is built once against whichever abi ran
#    first. All abis are built here and the remaining checksums are recorded as <also-trust>.

set -e

CONTRIB_ANDROID="$(dirname "$(readlink -e "$0")")"
CONTRIB="$CONTRIB_ANDROID"/..
CACHEDIR="$CONTRIB_ANDROID/.cache"
OUTDIR="$CONTRIB_ANDROID/verification-metadata"

. "$CONTRIB"/build_tools_util.sh

# the abis make_apk.sh builds, in the order it builds them. the first one is what
# BarcodeScannerView ends up compiled against.
ABIS=(armeabi-v7a arm64-v8a x86_64)

if [ -z "$ANDROID_SDK_HOME" ] || [ -z "$ANDROID_NDK_HOME" ]; then
    fail "ANDROID_SDK_HOME/ANDROID_NDK_HOME not set: run this inside the builder container"
fi

# a warm gradle cache produces incomplete metadata, so use a scratch one and throw it away.
# this means everything is downloaded from scratch; it is slow on purpose.
GRADLE_HOME_TMP="$(mktemp -d -t elec-gradle-verif-XXXXXX)"
cleanup() {
    info "removing scratch gradle home"
    rm -rf "$GRADLE_HOME_TMP"
}
trap cleanup EXIT
export GRADLE_USER_HOME="$GRADLE_HOME_TMP"
info "using scratch GRADLE_USER_HOME=$GRADLE_USER_HOME"

export ELEC_WRITE_VERIFICATION_METADATA=1

# force every library to actually rebuild, so every gradle invocation runs and records
info "clearing cached AARs and local maven repo"
rm -rf "$CACHEDIR/aars" "$CACHEDIR/m2"

for abi in "${ABIS[@]}"; do
    info "=== generating for $abi ==="
    "$CONTRIB_ANDROID"/make_barcode_scanner.sh "$abi" \
        || fail "make_barcode_scanner.sh failed for $abi"
done

mkdir -p "$OUTDIR"
copy_metadata() {
    local name=$1
    local project_dir=$2
    local src="$project_dir/gradle/verification-metadata.xml"

    if [ ! -f "$src" ]; then
        fail "no metadata generated at $src"
    fi
    cp "$src" "$OUTDIR/$name.xml"
    info "wrote $OUTDIR/$name.xml ($(grep -c '<component ' "$OUTDIR/$name.xml") components)"
}

copy_metadata zxingcpp           "$CACHEDIR/builds/zxing-cpp/wrappers/aar"
copy_metadata cameraview         "$CACHEDIR/builds/CameraView"
copy_metadata barcodescannerview "$CACHEDIR/builds/BarcodeScannerView"

# record the other abis' zxing-cpp checksums as <also-trust>, so a single-abi build (which
# leaves a different aar in the local maven repo) still verifies.
info "adding <also-trust> for the per-abi zxing-cpp checksums"
ZXING_SUMS=()
for abi in "${ABIS[@]}"; do
    f=$(ls "$CACHEDIR/aars"/zxing-cpp-"$abi"-*.aar 2>/dev/null | head -1)
    [ -n "$f" ] || fail "no zxing-cpp aar cached for $abi"
    ZXING_SUMS+=("$(sha256sum "$f" | cut -d' ' -f1)")
done

python3 - "$OUTDIR/barcodescannerview.xml" "${ZXING_SUMS[@]}" <<'EOF'
import io, re, sys

path, sums = sys.argv[1], sys.argv[2:]
s = io.open(path, encoding='utf-8').read()

m = re.search(r'<artifact name="(zxing-cpp-[^"]*\.aar)">\s*\n\s*'
              r'<sha256 value="([0-9a-f]{64})" origin="([^"]*)"/>', s)
if not m:
    sys.exit("could not find the zxing-cpp aar entry in %s" % path)
artifact, primary, origin = m.group(1), m.group(2), m.group(3)
others = [c for c in sums if c != primary]
if len(others) != len(sums) - 1:
    sys.exit("the recorded checksum %s is not one of the built abis" % primary)

ind = "               "
repl = ('<artifact name="%s">\n            <sha256 value="%s" origin="%s">\n' % (artifact, primary, origin)
        + ind + "<!-- the aar embeds jni/<abi>/libzxingcpp_android.so, so it has one\n"
        + ind + "     legitimate checksum per abi; barcodescannerview is built once,\n"
        + ind + "     against whichever abi make_apk.sh built first -->\n"
        + "".join(ind + '<also-trust value="%s"/>\n' % c for c in others)
        + "            </sha256>")
s = s[:m.start()] + repl + s[m.end():]
io.open(path, 'w', encoding='utf-8').write(s)
print("  primary %s, also-trust %s" % (primary[:16], ", ".join(c[:16] for c in others)))
EOF

info "done. review the diff in $OUTDIR and commit it."
info "note the AAR cache was cleared, so the next make_barcode_scanner.sh run rebuilds everything."
