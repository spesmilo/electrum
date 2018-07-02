#!/bin/bash
here=$(dirname "$0")
test -n "$here" -a -d "$here" || exit
cd $here

if ! which osslsigncode > /dev/null 2>&1; then
    echo "Please install osslsigncode"
    exit
fi

# exit if command fails
set -e

mkdir -p signed >/dev/null 2>&1
mkdir -p signed/stripped >/dev/null 2>&1

version=`python3 -c "import electrum_ltc; print(electrum_ltc.version.ELECTRUM_VERSION)"`

echo "Found $(ls dist/*.exe | wc -w) files to verify."

for mine in $(ls dist/*.exe); do
    echo "---------------"
    f=$(basename $mine)
    echo "Downloading https://electrum-ltc.org/download/$f"
    wget -q https://electrum-ltc.org/download/$f -O signed/$f
    out="signed/stripped/$f"
    size=$( wc -c < $mine )
    # Step 1: Remove PE signature from signed binary
    osslsigncode remove-signature -in signed/$f -out $out > /dev/null 2>&1
    # Step 2: Remove checksum and padding from signed binary
    python3 <<EOF
pe_file = "$out"
size= $size
with open(pe_file, "rb") as f:
    binary = bytearray(f.read())
pe_offset = int.from_bytes(binary[0x3c:0x3c+4], byteorder="little")
checksum_offset = pe_offset + 88
for b in range(4):
    binary[checksum_offset + b] = 0
l = len(binary)
n = l - size
if n > 0:
   if binary[-n:] != bytearray(n):
       print('expecting failure for', str(pe_file))
   binary = binary[:size]
with open(pe_file, "wb") as f:
    f.write(binary)
EOF
    chmod +x $out
    if cmp -s $out $mine; then
	echo "Success: $f"
	gpg --sign --armor --detach signed/$f
    else
	echo "Failure: $f"
    fi
done
