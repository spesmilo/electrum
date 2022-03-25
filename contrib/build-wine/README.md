# Windows binaries

✓ _These binaries should be reproducible, meaning you should be able to generate
   binaries that match the official releases._

This assumes an Ubuntu (x86_64) host, but it should not be too hard to adapt to another
similar system.

1. Install Docker

    See `contrib/docker_notes.md`.

    Note: older versions of Docker might not work well
    (see [#6971](https://github.com/spesmilo/electrum/issues/6971)).
    If having problems, try to upgrade to at least `docker 20.10`.

2. Build Windows binaries

    ```
    $ ./build.sh
    ```
    If you want reproducibility, try instead e.g.:
    ```
    $ ELECBUILD_COMMIT=HEAD ELECBUILD_NOCACHE=1 ./build.sh
    ```

3. The generated binaries are in `./contrib/build-wine/dist`.



## Code Signing

Electrum Windows builds are signed with a Microsoft Authenticode™ code signing
certificate in addition to the GPG-based signatures.

The advantage of using Authenticode is that Electrum users won't receive a 
Windows SmartScreen warning when starting it.

The release signing procedure involves a signer (the holder of the
certificate/key) and one or multiple trusted verifiers:


| Signer                                                    | Verifier                             |
|-----------------------------------------------------------|--------------------------------------|
| Build .exe files using `make_win.sh`                      |                                      |
| Sign .exe with `./sign.sh`                                |                                      |
| Upload signed files to download server                    |                                      |
|                                                           | Build .exe files using `make_win.sh` |
|                                                           | Compare files using `unsign.sh`      |
|                                                           | Sign .exe file using `gpg -b`        |

| Signer and verifiers:                                                                            |
|--------------------------------------------------------------------------------------------------|
| Upload signatures to 'electrum-signatures' repo, as `$version/$filename.$builder.asc`            |



## Verify Integrity of signed binary

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

## FAQ

### How to investigate diff between binaries if reproducibility fails?
`pyi-archive_viewer` is needed, for that run `$ pip install pyinstaller`.
As a first pass overview, run:
```
pyi-archive_viewer -l electrum-*.exe1 > f1
pyi-archive_viewer -l electrum-*.exe2 > f2
diff f1 f2 > d
cat d
```
Then investigate manually:
```
$ pyi-archive_viewer electrum-*.exe1
? help
```
