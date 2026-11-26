Building macOS binaries
=======================

✓ _These binaries should be reproducible, meaning you should be able to generate
   binaries that match the official releases._

- _Minimum supported target system (i.e. what end-users need): macOS 12_

This guide explains how to build Electrum binaries for macOS systems.


## Building the binary

This needs to be done on a system running macOS or OS X.

The script is only tested on Intel-based (x86_64) Macs, and the built binaries
target `x86_64` and `arm64`.

Notes about compatibility with different macOS versions:
- The minimum supported macOS version is defined by `MACOSX_DEPLOYMENT_TARGET`
  in `make_osx.sh`.
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

We currently build the release binaries on macOS 15, and these seem to run on
12 or newer.


#### Notes about reproducibility

- We recommend creating a VM with a macOS guest, e.g. using
  [OSX-KVM](https://github.com/kholia/OSX-KVM), and building there.
- The guest should run macOS 15 (15.3 or later).
- The unix username should be `vagrant`, and `electrum` should be cloned directly
  to the user's home dir: `/Users/vagrant/electrum`.
- Builders need to use the same version of Xcode; and note that
  full Xcode and Xcode commandline tools differ!
  We use the Xcode CLI tools. (version 16.4)

  Sanity checks:
    ```
    $ sw_vers  # note: OS version having different patch-level (15.8.x) is hopefully okay
    ProductName:		macOS
    ProductVersion:		15.8.2
    BuildVersion:		24H232
    $ xcode-select -p
    /Library/Developer/CommandLineTools
    $ xcrun --show-sdk-path
    /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
    $ pkgutil --pkg-info=com.apple.pkg.CLTools_Executables
    package-id: com.apple.pkg.CLTools_Executables
    version: 16.4.0.0.1.1747106510
    volume: /
    location: /
    install-time: XXXXXXXXXX
    $ gcc --version
    Apple clang version 17.0.0 (clang-1700.0.13.5)
    Target: x86_64-apple-darwin24.6.0
    Thread model: posix
    InstalledDir: /Library/Developer/CommandLineTools/usr/bin
    ```
- Installing extraneous brew packages can result in build differences.
  For example, pyinstaller seems to pick up and bundle brew-installed `libffi`.
  So having a dedicated "electrum binary builder macOS VM" is recommended.
- Make sure that you are building from a fresh clone of electrum
  (or run e.g. `git clean -ffxd` to rm all local changes).


#### Tips for the OSX-KVM VM setup

- The virt-manager application provides a convenient GUI for managing the VM.
- For macOS 15, the `-cpu` argument in OSX-KVM's `macOS-libvirt-Catalina.xml` must use
  `Skylake-Client,-hle,-rtm` instead of `Penryn`, as in
  [`OpenCore-Boot.sh`](https://github.com/kholia/OSX-KVM/blob/4c378a4b5e0b219783683012bec680325eb40719/OpenCore-Boot.sh#L36-L37).
- If the installer asks to connect a Bluetooth keyboard or doesn't react to keyboard input,
  remove the `ports="..."` attribute from the `qemu-xhci` controller.
- If the installer freezes (vCPU threads at 100%, no disk I/O), install with 1 vCPU
  and add more afterwards.
- You can remove the `BaseSystem.img` installer disk from the VM once macOS is installed.
- SSH: enable System Settings > General > Sharing > Remote Login, and forward a host port
  to the guest's port 22, e.g. `-netdev user,id=net0,hostfwd=tcp::2222-:22` as in
  `OpenCore-Boot.sh`, then `ssh -p 2222 vagrant@localhost`.
- The `PerfPowerServices` daemon can get stuck in a busy loop and keep a core at 100%.
  Suspending it at every boot from root's crontab (`sudo crontab -e`)
  works as a hack to stop this:
  `@reboot sleep 60; /usr/bin/pkill -STOP -f '^/usr/libexec/PerfPowerServices( |$)'`


#### 1. Install the Xcode CLI tools

    touch /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress
    sudo softwareupdate --install "Command Line Tools for Xcode-16.4"
    rm /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress


#### 2. Build Electrum

    cd electrum
    ./contrib/osx/make_osx.sh

This creates an unsigned `Electrum.app` folder and `.dmg` file for each built
architecture.

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

Every user can verify that the official binaries were created from the source code in this
repository.

1. Build your own binaries as described above.
2. Use the provided `compare_dmg` script to compare the binaries you built with
   the official release binaries.
    ```
    $ ./contrib/osx/compare_dmg dist/electrum-$VERSION-x86_64-unsigned.dmg electrum-$VERSION-x86_64.dmg
    $ ./contrib/osx/compare_dmg dist/electrum-$VERSION-arm64-unsigned.dmg electrum-$VERSION-arm64.dmg
    ```
   The `compare_dmg` script is mostly only needed as the official release binaries are
   codesigned and notarized. Otherwise, the built `.app` bundles should be byte-identical.
   (Note that we are using `hdutil` to create the `.dmg`, and its output is not
   deterministic, but we cannot compare the `.dmg` files directly anyway as they contain
   codesigned files)


## FAQ

### What is macOS "codesigning" and "notarization"?

Codesigning is the macOS OS-native signing of executables/shared-libs,
that needs to be done using an ~x509-like certificate that chains back to Apple's root CA.
Once a developer certificate is obtained from Apple, it can be used to codesign locally
on a dev machine.

Notarization is a further step usually done after, which entails uploading a distributable
over the network to the Apple mothership central server, which runs some arbitrary checks on it,
and if it finds the file ok, the central server gives the dev a notarization staple.
This staple can then be optionally "attached" to the distributable, mutating it, which we do.
(If the staple is not attached, enduser machines request it from the mothership at runtime.)

Both these steps should be done during the build process.

### What is "codesigned" and/or "notarized", re the official release?

- `make_osx.sh` builds a `.app`, which is unsigned/unnotarized
  - at this point, this `.app` is ~"byte-for-byte" reproducible
    - this is the sanity-check hash printed at the end of `make_osx.sh`
  - `make_osx.sh` creates a `.dmg` from the `.app`
    - this `.dmg` is not used for the official release at all, but used as the basis of
      testing reproducibility using the `compare_dmg` script
- `sign_osx.sh` codesigns the `.app` (mutating it)
- `sign_osx.sh` -> `notarize_app.sh` notarizes the `.app` (mutating it)
- `sign_osx.sh` creates a `.dmg` from the `.app`
- `sign_osx.sh` codesigns the `.dmg` (mutating it)
  - this `.dmg` becomes the official release distributable

That is, the official release `.dmg` is codesigned but NOT notarized.
It contains a `.app`, which is codesigned AND notarized.

### How to check if a file is codesigned?

Both the `.dmg` and the contained `.app` are codesigned:
```
$ codesign --verify --deep --strict --verbose=2 $HOME/Desktop/electrum-4.5.8.dmg && echo "signed"
/Users/vagrant/Desktop/electrum-4.5.8.dmg: valid on disk
/Users/vagrant/Desktop/electrum-4.5.8.dmg: satisfies its Designated Requirement
signed
```
```
$ codesign --verify --deep --strict --verbose=1 $HOME/Desktop/Electrum-4.5.8.app && echo "signed"
/Users/vagrant/Desktop/Electrum-4.5.8.app: valid on disk
/Users/vagrant/Desktop/Electrum-4.5.8.app: satisfies its Designated Requirement
signed
```

Also see `$ codesign -dvvv $HOME/Desktop/electrum-4.5.8.dmg`

### How to check if a file is notarized?

The outer `.dmg` is NOT notarized, but the inner `.app` is notarized:
```
$ spctl -a -vvv -t install $HOME/Desktop/electrum-4.5.8.dmg
/Users/vagrant/Desktop/electrum-4.5.8.dmg: rejected
source=Unnotarized Developer ID
origin=Developer ID Application: Electrum Technologies GmbH (L6P37P7P56)
```
```
$ spctl -a -vvv -t install $HOME/Desktop/Electrum-4.5.8.app
/Users/vagrant/Desktop/Electrum-4.5.8.app: accepted
source=Notarized Developer ID
origin=Developer ID Application: Electrum Technologies GmbH (L6P37P7P56)
```

### How to simulate the signing procedure?

It is possible to run `sign_osx.sh` using a self-signed certificate to test the
signing procedure without using a production certificate.

Note that the notarization process will be skipped as it is not possible to notarize
an executable with Apple using a self-signed certificate.

#### To generate a self-signed certificate, inside your **MacOS VM**:

1. Open the `Keychain Access` application.
2. In the menubar go to `Keychain Access` > `Certificate Assistant` > `Create a Certificate...`
3. Set a name (e.g. `signing_dummy`)
4. Change `Certificate Type` to *'Code Signing'*
5. Click `Create` and `Continue`.

You now have a self-signed certificate `signing_dummy` added to your `login` keychain.

#### Fix "Access Control" settings for private key (of new cert)

If you try using your cert with `codesign`, it will fail:
```
% cp -f /bin/ls ./CODESIGN_TEST
% set +e
% codesign -s "signing_dummy" --dryrun -f ./CODESIGN_TEST
./CODESIGN_TEST: replacing existing signature
./CODESIGN_TEST: errSecInternalComponent
```

To fix this, find the corresponding private key (for the cert) also named `signing_dummy`,
in `Keychain Access`.
- Right-click the private key item > `Get Info` > `Access Control`.
- There is a list of allowed apps in the popup that can access the private key.
- Click the small `+` (plus) icon. Then press `Win`+`Shift`+`G`: go to folder: `/usr/bin/codesign`,
  and add the codesign executable to the list.
- Click `Save Changes`.

Now try again:
```
% security unlock-keychain login.keychain
% codesign -s "signing_dummy" --dryrun -f ./CODESIGN_TEST
./CODESIGN_TEST: replacing existing signature
```

#### To sign the executables with the self-signed certificate:

Assuming you have the two unsigned outputs of `make_osx.sh` inside `~/electrum/dist`
(e.g. `Electrum.app` and `electrum-4.5.4-1368-gc8db684cc-unsigned.dmg`).

In `~/electrum` run:

`$ CODESIGN_CERT="signing_dummy" ./contrib/osx/sign_osx.sh`

After `sign_osx.sh` finished, you will have a new `*.dmg` inside `electrum/dist`
(without the `-unsigned` postfix) which is signed with your certificate.

#### To compare the unsigned executable with the self-signed executable:

Running `compare_dmg` should succeed:

`$ ./electrum/contrib/osx/compare_dmg <unsigned executable> <self-signed executable>`


### Codesigning with production cert

Keys and certificates are imported with the GUI:

 - Import the intermediate certificate DeveloperIDG2CA.cer from https://www.apple.com/certificateauthority/
 - Import the Electrum certificate
 - Import codesigning private key (p12 file)
 - Leave trust settings to "Use System Defaults"

Sanity check:
```
% security find-identity -v -p codesigning
1) 334066EA45A0F71D0DCCC3BDC36BC9E04CAF3432 "Developer ID Application: Electrum Technologies GmbH (L6P37P7P56)"
   1 valid identities found
```


#### "Trust" settings of developer certificate must be set to "Use System Defaults"

Fiddling with the trust settings of the cert produces all kinds of obscure results/errors.

Error1:
```
% export CODESIGN_CERT="Developer ID Application: Electrum Technologies GmbH (L6P37P7P56)"
% cp -f /bin/ls ./CODESIGN_TEST
% codesign -s "$CODESIGN_CERT" -f ./CODESIGN_TEST
./CODESIGN_TEST: replacing existing signature
Warning: unable to build chain to self-signed root for signer "Developer ID Application: Electrum Technologies GmbH (L6P37P7P56)"
./CODESIGN_TEST: errSecInternalComponent
```

We saw error1 when multiple use-cases had trust settings set to "Always Trust".


Error2:
```
% export CODESIGN_CERT="Developer ID Application: Electrum Technologies GmbH (L6P37P7P56)"
% cp -f /bin/ls ./CODESIGN_TEST
% codesign -s "$CODESIGN_CERT" -f --timestamp CODESIGN_TEST
CODESIGN_TEST: replacing existing signature
% codesign --verify --strict --verbose=2 CODESIGN_TEST
CODESIGN_TEST: valid on disk
CODESIGN_TEST: does not satisfy its designated Requirement
```

We saw error2 when only "Code Signing" was set to "Always Trust".


Solution:
- Open the `Keychain Access` application.
- Right-click the certificate item > `Get Info`.
- Open the `Trust` dropdown.
- Set: "When using this certificate" to "Use System Defaults"

Note: cannot reproduce issue using self-signed "signing_dummy" cert, only using prod cert.
