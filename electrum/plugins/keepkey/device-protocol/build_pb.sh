#!/bin/bash
set -e

PLUGIN_KEEPKEY="$(dirname "$(readlink -e "$0")")/.."
cd "$PLUGIN_KEEPKEY/device-protocol"

echo "Building with protoc version: $(protoc --version)"
for i in messages types exchange ; do
    protoc --python_out="$PLUGIN_KEEPKEY/keepkeylib/" -I/usr/include -I. $i.proto
    i=${i/-/_}
    sed -i -Ee 's/^import ([^.]+_pb2)/from . import \1/' "$PLUGIN_KEEPKEY"/keepkeylib/"$i"_pb2.py
done

sed -i 's/5000\([2-5]\)/6000\1/g' "$PLUGIN_KEEPKEY"/keepkeylib/types_pb2.py
