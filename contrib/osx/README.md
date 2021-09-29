Building macOS binaries
=======================

✓ _This binary should be reproducible, meaning you should be able to generate
   binaries that match the official releases._

This guide explains how to build Electrum binaries for macOS systems.


## Building the binary

This needs to be done on a system running macOS or OS X.

Notes about compatibility with different macOS versions:
- In general the binary is not guaranteed to run on an older version of macOS
  than what the build machine has. This is due to bundling the compiled Python into
  the [PyInstaller binary](https://github.com/pyinstaller/pyinstaller/issues/1191).
- The [bundled version of Qt](https://github.com/spesmilo/electrum/issues/3685) also
  imposes a minimum supported macOS version.
- If you want to build binaries that conform to the macOS "Gatekeeper", so as to
  minimise the warnings users get, the binaries need to be codesigned with a
  certificate issued by Apple, and starting with macOS 10.15 the binaries also
  need to be notarized by Apple's central server. The catch is that to be able to build
  binaries that Apple will notarise (due to the requirements on the binaries themselves,
  e.g. hardened runtime) the build machine needs at least macOS 10.14.
  See [#6128](https://github.com/spesmilo/electrum/issues/6128).

We currently build the release binaries on macOS 10.14.6, and these seem to run on
10.13 or newer.

Before starting, you should install `brew`.


#### Notes about reproducibility

- We recommend creating a VM with a macOS guest, e.g. using VirtualBox,
  and building there.
- The guest should run macOS 10.14.6 (that specific version).
- The unix username should be `vagrant`, and `electrum` should be cloned directly
  to the user's home dir: `/Users/vagrant/electrum`.
- Builders need to use the same version of Xcode; and note that
  full Xcode and Xcode commandline tools differ!
  You should build with Xcode 11.3.1 (full Xcode).
  The path for Xcode should be exactly as follows:
    ```
    $ xcode-select -p
    /Users/vagrant/Downloads/Xcode.app/Contents/Developer
    $ xcrun --show-sdk-path
    /Users/vagrant/Downloads/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk
    ```
  Note: make sure neither command above refers to the Xcode command line tools!
  If so, rename the cli tools, e.g.
    ```
    $ mv /Library/Developer/CommandLineTools /Library/Developer/CommandLineTools2
    ```
  As a sanity check, make sure `$ gcc --version` consistently refers to the full Xcode.
- Make sure that you are building from a fresh clone of electrum
  (or run e.g. `git clean -ffxd` to rm all local changes).


#### 1. Get Xcode

Notarizing the application requires full Xcode
(not just command line tools as that is missing `altool`).

Get it from [here](https://developer.apple.com/download/more/).
Unfortunately, you need an "Apple ID" account.

(note: the last Xcode that runs on macOS 10.14.6 is Xcode 11.3.1)

After downloading, uncompress it.

Make sure it is the "selected" xcode (e.g.):

    sudo xcode-select -s $HOME/Downloads/Xcode.app/Contents/Developer/


#### 2. Build Electrum

    cd electrum
    ./contrib/osx/make_osx

This creates both a folder named Electrum.app and the .dmg file.

If you want the binaries codesigned for MacOS and notarised by Apple's central server,
provide these env vars to the `make_osx` script:

    CODESIGN_CERT="Developer ID Application: Electrum Technologies GmbH (L6P37P7P56)" \
    APPLE_ID_USER="me@email.com" \
    APPLE_ID_PASSWORD="1234" \
    ./contrib/osx/make_osx


## Verifying reproducibility and comparing against official binary

Every user can verify that the official binary was created from the source code in this 
repository.

1. Build your own binary as described above.
2. Use the provided `compare_dmg` script to compare the binary you built with
   the official release binary.
    ```
    $ ./contrib/osx/compare_dmg dist/electrum-*.dmg electrum_dmg_official_release.dmg
    ```
   The `compare_dmg` script is mostly only needed as the official release binary is
   codesigned and notarized. Otherwise, the built `.app` bundles should be byte-identical.
   (Note that we are using `hdutil` to create the `.dmg`, and its output is not
   deterministic, but we cannot compare the `.dmg` files directly anyway as they contain
   codesigned files)
