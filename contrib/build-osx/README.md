Building Mac OS binaries
========================

This guide explains how to build Electrum-LTC binaries for macOS systems.

The build process consists of two steps:

## 1. Building the binary

This needs to be done on a system running macOS or OS X. We use El Capitan (10.11.6) as building it on High Sierra
makes the binaries incompatible with older versions. 

Before starting, make sure that the Xcode command line tools are installed (e.g. you have `git`).


    cd electrum-ltc
    ./contrib/build-osx/make_osx
    
This creates a folder named Electrum-LTC.app.

## 2. Building the image 
The usual way to distribute macOS applications is to use image files containing the 
application. Although these images can be created on a Mac with the built-in `hdiutil`,
they are not deterministic.

Instead, we use the toolchain that Bitcoin uses: genisoimage and libdmg-hfsplus.
These tools do not work on macOS, so you need a separate Linux machine (or VM).

Copy the Electrum-LTC.app directory over and install the dependencies, e.g.:

    apt install libcap-dev cmake make gcc faketime
    
Then you can just invoke `package.sh` with the path to the app:

    cd electrum-ltc
    ./contrib/build-osx/package.sh ~/Electrum-LTC.app/
