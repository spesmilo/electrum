#!/bin/bash

# MacOS build instructions

/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

# Optionally (this is bad practice but works if you're stuck)
sudo chown -R "$USER":admin /usr/local
sudo chown -R "$USER":admin /Library/Caches/Homebrew

# Python setuptools
curl https://bootstrap.pypa.io/ez_setup.py -o - | python3

# Setup
python3 setup.py install
