Windows Binary Builds
=====================

These scripts can be used for cross-compilation of Windows Electrum executables from Linux/Wine.
Produced binaries are deterministic so you should be able to generate binaries that match the official releases.


Usage:


1. Install the following dependencies:

 - dirmngr
 - gpg
 - Wine (>= v2)


For example:


```
$ sudo apt-get install wine-development dirmngr gnupg2
$ sudo ln -sf /usr/bin/wine-development /usr/local/bin/wine
$ wine --version
 wine-2.0 (Debian 2.0-3+b2)
```

or

```
$ pacman -S wine gnupg
$ wine --version
 wine-2.21
```

2. Make sure `/opt` is writable by the current user.
3. Run `build.sh`.
4. The generated binaries are in `./dist`.


Code Signing
============

Electrum Windows builds are signed with a Microsoft Authenticode™ code signing
certificate in addition to the GPG-based signatures.

The advantage of using Authenticode is that Electrum users won't receive a 
Windows SmartScreen warning when starting it.

The release signing procedure involves a signer (the holder of the
certificate/key) and one or multiple trusted verifiers:


| Signer                                                    | Verifier                          |
|-----------------------------------------------------------|-----------------------------------|
| Build .exe files using `build.sh`                         |                                   |
|                                                           | Build .exe files using `build.sh` |
|                                                           | Sign .exe files using `gpg -b`    |
|                                                           | Send signatures to signer         |
| Place signatures as `$filename.$builder.asc` in `./dist`  |                                   |
| Run `./sign.sh`                                           |                                   |


`sign.sh` will check if the signatures match the signer's files. This ensures that the signer's
build environment is not compromised and that the binaries can be reproduced by anyone.
