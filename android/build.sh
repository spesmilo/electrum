#!/bin/bash
set -eu

cd $(dirname $0)/..

docker build -t ec-android -f android/Dockerfile .
container_name=$(docker create ec-android)
docker cp $container_name:/root/android/app/build/outputs/apk/release android
docker rm $container_name
