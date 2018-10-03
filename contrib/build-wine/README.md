Windows Binary Builds
=====================

These scripts can be used for cross-compilation of Windows Electrum executables from Linux/Wine.

For reproducible builds, see the `docker` folder.


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
[that script](https://github.com/spesmilo/electrum/blob/master/.travis.yml) might help.

2. Make sure `/opt` is writable by the current user.
3. Run `build.sh`.
4. The generated binaries are in `./dist`.
