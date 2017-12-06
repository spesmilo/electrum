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
