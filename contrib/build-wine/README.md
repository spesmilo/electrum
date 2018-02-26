Windows Binary Builds
=====================

These scripts can be used for cross-compilation of Windows Electrum executables from Linux/Wine.
Produced binaries are deterministic, so you should be able to generate binaries that match the official releases. 


Usage:


1. Install the following dependencies:

 - dirmngr
 - gpg
 - 7Zip
 - Wine (>= v2)


For example:


```
$ sudo apt-get install wine-development dirmngr gnupg2 p7zip-full
$ wine --version
 wine-2.0 (Debian 2.0-3+b2)
```

or

```
$ pacman -S wine gnupg
$ wine --version
 wine-2.21
```

If during execution you run into any errors related to Wine, remove all previous Wine packages (including all packages that depend on it, like wine-mono and winetricks) and install Ubuntu's [official Wine package](https://wiki.winehq.org/Ubuntu) with:
```
$ wget -nc https://dl.winehq.org/wine-builds/Release.key
$ sudo apt-key add Release.key
$ sudo apt-add-repository https://dl.winehq.org/wine-builds/ubuntu/
$ sudo apt-get update
$ sudo apt-get install --install-recommends winehq-stable
$ wine --version
wine-3.2
```

2. Make sure `/opt` is writable by the current user.
3. Run `build.sh`.
4. The generated binaries are in `./dist`.
