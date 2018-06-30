Windows Binary Builds
=====================

These scripts can be used for cross-compilation of Windows Electrum-LTC executables from Linux/Wine.
Produced binaries are deterministic, so you should be able to generate binaries that match the official releases. 


Usage:


1. Install the following dependencies:

 - dirmngr
 - gpg
 - 7Zip
 - Wine (>= v2)
 - (and, for building libsecp256k1)
   - mingw-w64
   - autotools-dev
   - autoconf
   - libtool


For example:

```
$ sudo apt-get install wine-development dirmngr gnupg2 p7zip-full
$ sudo apt-get install mingw-w64 autotools-dev autoconf libtool
```

The binaries are also built by Travis CI, so if you are having problems,
[that script](https://github.com/pooler/electrum-ltc/blob/master/.travis.yml) might help.

2. Make sure `/opt` is writable by the current user.
3. Run `build.sh`.
4. The generated binaries are in `./dist`.


Code Signing
============

Electrum-LTC Windows builds are signed with a Microsoft Authenticode™ code signing
certificate in addition to the GPG-based signatures.

The advantage of using Authenticode is that Electrum-LTC users won't receive a 
Windows SmartScreen warning when starting it.

The release signing procedure involves a signer (the holder of the
certificate/key) and one or multiple trusted verifiers:


| Signer                                                    | Verifier                          |
|-----------------------------------------------------------|-----------------------------------|
| Build .exe files using `build.sh`                         |                                   |
| Sign .exe with `./sign.sh`                                |                                   |
| Upload signed files to download server                    |                                   |
|                                                           | Build .exe files using `build.sh` |
|                                                           | Compare files using `unsign.sh`   |
|                                                           | Sign .exe file using `gpg -b`     |

| Signer and verifiers:
| Upload signatures to 'electrum-ltc-signatures' repo, as `$version/$filename.$builder.asc`         |




Verify Integrity of signed binary
=================================

Every user can verify that the official binary was created from the source code in this 
repository. To do so, the Authenticode signature needs to be stripped since the signature
is not reproducible.

This procedure removes the differences between the signed and unsigned binary:

1. Remove the signature from the signed binary using osslsigncode or signtool.
2. Set the COFF image checksum for the signed binary to 0x0. This is necessary
   because pyinstaller doesn't generate a checksum.
3. Append null bytes to the _unsigned_ binary until the byte count is a multiple
   of 8.

The script `unsign.sh` performs these steps.
