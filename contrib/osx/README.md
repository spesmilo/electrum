Building macOS binaries
=======================

✓ _This binary should be reproducible, meaning you should be able to generate
   binaries that match the official releases._

This guide explains how to build Electrum binaries for macOS systems.


## Building the binary

This needs to be done on a system running macOS or OS X.

The script is only tested on Intel-based (x86_64) Macs, and the binary built
targets `x86_64` currently.

Notes about compatibility with different macOS versions:
- In general the binary is not guaranteed to run on an older version of macOS
  than what the build machine has. This is due to bundling the compiled Python into
  the [PyInstaller binary](https://github.com/pyinstaller/pyinstaller/issues/1191).
- The [bundled version of Qt](https://github.com/spesmilo/electrum/issues/3685) also
  imposes a minimum supported macOS version.
- If you want to build binaries that conform to the macOS "Gatekeeper", so as to
  minimise the warnings users get, the binaries need to be codesigned with a
  certificate issued by Apple, and starting with macOS 10.15 (targets) the binaries also
  need to be notarized by Apple's central server. To be able to build
  binaries that Apple will notarize (due to the requirements on the binaries themselves,
  e.g. hardened runtime) the build machine needs at least macOS 10.14.
  See [#6128](https://github.com/spesmilo/electrum/issues/6128).
  - There are two tools that can be used to notarize a binary, both part of Xcode:
    the old `altool` and the newer `notarytool`. `altool`
    [was deprecated](https://developer.apple.com/news/?id=y5mjxqmn) by Apple.
    `notarytool` requires Xcode 13+, and that in turn requires macOS 11.3+.

We currently build the release binaries on macOS 11.7.10, and these seem to run on
11 or newer.


#### Notes about reproducibility

- We recommend creating a VM with a macOS guest, e.g. using VirtualBox,
  and building there.
- The guest should run macOS 11.7.10 (that specific version).
- The unix username should be `vagrant`, and `electrum` should be cloned directly
  to the user's home dir: `/Users/vagrant/electrum`.
- Builders need to use the same version of Xcode; and note that
  full Xcode and Xcode commandline tools differ!
  We use the Xcode CLI tools as installed by brew. (version 13.2)

  Sanity checks:
    ```
    $ xcode-select -p
    /Library/Developer/CommandLineTools
    $ xcrun --show-sdk-path
    /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
    $ pkgutil --pkg-info=com.apple.pkg.CLTools_Executables
    package-id: com.apple.pkg.CLTools_Executables
    version: 13.2.0.0.1.1638488800
    volume: /
    location: /
    install-time: XXXXXXXXXX
    groups: com.apple.FindSystemFiles.pkg-group
    $ gcc --version
    Configured with: --prefix=/Library/Developer/CommandLineTools/usr --with-gxx-include-dir=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/c++/4.2.1
    Apple clang version 13.0.0 (clang-1300.0.29.30)
    Target: x86_64-apple-darwin20.6.0
    Thread model: posix
    InstalledDir: /Library/Developer/CommandLineTools/usr/bin
    ```
- Installing extraneous brew packages can result in build differences.
  For example, pyinstaller seems to pick up and bundle brew-installed `libffi`.
  So having a dedicated "electrum binary builder macOS VM" is recommended.
- Make sure that you are building from a fresh clone of electrum
  (or run e.g. `git clean -ffxd` to rm all local changes).


#### 1. Install brew

Install [`brew`](https://brew.sh/).

Let brew install the Xcode CLI tools.


#### 2. Build Electrum

    cd electrum
    ./contrib/osx/make_osx.sh

This creates both a folder named Electrum.app and the .dmg file (both unsigned).

##### 2.1. For release binaries, here be dragons

If you want the binaries codesigned for macOS and notarised by Apple's central server,
also run the `sign_osx.sh` script:

    CODESIGN_CERT="Developer ID Application: Electrum Technologies GmbH (L6P37P7P56)" \
    APPLE_TEAM_ID="L6P37P7P56" \
    APPLE_ID_USER="me@email.com" \
    APPLE_ID_PASSWORD="1234" \
    ./contrib/osx/sign_osx.sh

(note: `APPLE_ID_PASSWORD` is an app-specific password, *not* the account password)


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
