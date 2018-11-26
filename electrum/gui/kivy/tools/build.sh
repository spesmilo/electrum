#!/usr/bin/env bash

pushd electrum/gui/kivy
make theming
popd

sudo ./contrib/make_packages

./contrib/make_apk
