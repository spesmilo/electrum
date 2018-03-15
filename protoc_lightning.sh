#!/bin/sh -ex
if [ ! -d $HOME/go/src/github.com/grpc-ecosystem ]; then
  # from readme in https://github.com/grpc-ecosystem/grpc-gateway
  go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
  go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger
  go get -u github.com/golang/protobuf/protoc-gen-go
fi
if [ ! -d $HOME/go/src/github.com/lightningnetwork/lnd ]; then
  echo "You need an lnd with electrum-bridge (ysangkok/lnd maybe?) checked out since we implement the interface from there, and need it to generate code"
  exit 1
fi
mkdir -p lib/ln || true
touch lib/__init__.py
~/go/bin/protoc -I$HOME/include -I$HOME/go/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis --python_out=lib/ln $HOME/go/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis/google/api/*.proto
python3 -m grpc_tools.protoc -I $HOME/go/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis --proto_path $HOME/go/src/github.com/lightningnetwork/lnd/electrum-bridge --python_out=lib/ln --grpc_python_out=lib/ln ~/go/src/github.com/lightningnetwork/lnd/electrum-bridge/rpc.proto
