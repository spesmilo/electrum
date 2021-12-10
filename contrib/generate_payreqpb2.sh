#!/bin/bash
# Generates the file paymentrequest_pb2.py

CONTRIB="$(dirname "$(readlink -e "$0")")"
EL="$CONTRIB"/../electrum

if ! which protoc > /dev/null 2>&1; then
    echo "Please install 'protoc'"
    echo "If you're on Debian, try 'sudo apt install protobuf-compiler'?"
    exit 1
fi

protoc --proto_path="$EL" --python_out="$EL" "$EL"/paymentrequest.proto
