#!/bin/sh
protoc --python_out=. --proto_path=./protobuf fusion.proto
