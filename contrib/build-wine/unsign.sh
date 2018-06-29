#!/bin/bash
here=$(dirname "$0")
test -n "$here" -a -d "$here" || exit
cd $here

if ! which osslsigncode > /dev/null 2>&1; then
    echo "Please install osslsigncode"
    exit
fi

if [ $# -ne 2 ]; then
    echo "Usage: $0 signed_binary unsigned_binary"
    exit
fi

out="$1-stripped.exe"

set -ex

echo "Step 1: Remove PE signature from signed binary"
osslsigncode remove-signature -in $1 -out $out

echo "Step 2: Remove checksum from signed binary"
python3 <<EOF
pe_file = "$out"
with open(pe_file, "rb") as f:
    binary = bytearray(f.read())

pe_offset = int.from_bytes(binary[0x3c:0x3c+4], byteorder="little")
checksum_offset = pe_offset + 88

for b in range(4):
    binary[checksum_offset + b] = 0

with open(pe_file, "wb") as f:
    f.write(binary)
EOF

bytes=$( wc -c < $2 )
bytes=$((8 - ($bytes%8)))
bytes=$(($bytes % 8))

echo "Step 3: Appending $bytes null bytes to unsigned binary"

truncate -s +$bytes $2

diff $out $2 && echo "Success!"
