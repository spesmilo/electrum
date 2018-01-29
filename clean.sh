#!/bin/bash

sudo rm -rf build/
sudo rm -rf dist/
sudo rm -rf Electrum-Egg*

sudo python3 setup.py install
