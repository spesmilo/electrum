Windows Binary Builds
=====================


These scripts can be used for cross-compilation of Windows Electron Cash executables from Linux/Wine.
Produced binaries are deterministic so you should be able to generate binaries that match the official releases.

Usage:
1. Install Wine 2, or Wine 3 e.g.

```
$ sudo apt-get install wine-development
$ sudo ln -sf /usr/bin/wine-development /usr/local/bin/wine
$ wine --version
 wine-2.0 (Debian 2.0-3+b2)
```

or

```
$ pacman -S wine
$ wine --version
 wine-2.21
```

2. Install the following dependencies:

 - dirmngr
 - gpg
 - 7Zip
 - Wine (>= v2)
 - (and, for building libsecp256k1)
   - mingw-w64
   - autotools-dev
   - autoconf
   - libtool

3. Make sure `/opt` is writable by the current user.
4. Run `build.sh [<git-ref>]`, where <git-ref> (e.g., 3.3.1) is the branch/tag
   you want to be checked out from official repo.
   (optional -- defaults a hardcoded tag found in build-electrum-git.sh )
   Note that build.sh may fail the first time after fetching gpg signatures.
   It should work correctly on the second try.
5. The generated binaries are in `dist`.
