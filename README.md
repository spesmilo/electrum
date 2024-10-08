# Electrum - Lightweight Bitcoin client

```
Licence: MIT Licence
Author: Thomas Voegtlin
Language: Python (>= 3.8)
Homepage: https://electrum.org/
```

[![Build Status](https://api.cirrus-ci.com/github/spesmilo/electrum.svg?branch=master)](https://cirrus-ci.com/github/spesmilo/electrum)
[![Test coverage statistics](https://coveralls.io/repos/github/spesmilo/electrum/badge.svg?branch=master)](https://coveralls.io/github/spesmilo/electrum?branch=master)
[![Help translate Electrum online](https://d322cqt584bo4o.cloudfront.net/electrum/localized.svg)](https://crowdin.com/project/electrum)


## Getting started

_(If you've come here looking to simply run Electrum,
[you may download it here](https://electrum.org/#download).)_

Electrum itself is pure Python, and so are most of the required dependencies,
but not everything. The following sections describe how to run from tar.gz or from source.

### Running from tar.gz

If you downloaded the official package (tar.gz), you can run
Electrum from its root directory without installing it on your
system; all the pure python dependencies are included in the 'packages'
directory. You will need to install a few system dependencies:

To use the desktop GUI (Qt5):

```
$ sudo apt-get install python3-pyqt6
```

Due to the need for fast symmetric ciphers,
[cryptography](https://github.com/pyca/cryptography) is required.
Install from your package manager:
```
$ sudo apt-get install python3-cryptography
```

To run Electrum from its root directory, just do:
```
$ ./run_electrum
```

This method currently lacks hardware wallet support.
If you need hardware wallet support, you should install as [described below](#install-to-a-python-virtualenv)


### Install to a python virtualenv

#### Create a python virtualenv

```commandline
$ python3 -m venv $HOME/electrum
```

When the `virtualenv` is created or already exists, activate it:

```commandline
$ . $HOME/electrum/bin/activate
```

#### Install electrum and dependencies

```commandline
$ pip install .[gui,crypto,hardware]
```

This will install Electrum and all required dependencies,
including for Qt desktop GUI and hardware wallets.

#### Not pure-python dependencies

For elliptic curve operations,
[libsecp256k1](https://github.com/bitcoin-core/secp256k1)
is a required dependency:
```
$ sudo apt-get install libsecp256k1-dev
```

Alternatively, when running from a cloned repository, a script is provided to build
libsecp256k1 yourself:
```
$ sudo apt-get install automake libtool
$ ./contrib/make_libsecp256k1.sh
```

For more information about hardware wallet dependencies,
[see this](https://github.com/spesmilo/electrum-docs/blob/master/hardware-linux.rst).

To run Electrum, just do:
```
$ electrum
```

Or, without first activating the `virtualenv`:

```commandline
$ $HOME/electrum/bin/electrum
```

### Development version (git clone)

_(For OS-specific instructions, see [here for Windows](contrib/build-wine/README_windows.md),
and [for macOS](contrib/osx/README_macos.md))_

#### Check out the code from GitHub:
```
$ git clone https://github.com/spesmilo/electrum.git
$ cd electrum
$ git submodule update --init
```

#### create and activate virtualenv

```commandline
$ python3 -m venv $HOME/electrum
$ . $HOME/electrum/bin/activate
```

#### Run install (this should install dependencies):
```
$ pip install -e .[gui,crypto,hardware]
```

Create translations (optional):
```
$ sudo apt-get install python3-requests gettext qttools5-dev-tools
$ ./contrib/pull_locale
```

Finally, to start Electrum:
```
$ ./run_electrum
```

### Run tests

Run unit tests with `pytest`:
```
$ pytest tests -v
```

To run a single file, specify it directly like this:
```
$ pytest tests/test_bitcoin.py -v
```

## Creating Binaries

- [Linux (tarball)](contrib/build-linux/sdist/README.md)
- [Linux (AppImage)](contrib/build-linux/appimage/README.md)
- [macOS](contrib/osx/README.md)
- [Windows](contrib/build-wine/README.md)
- [Android](contrib/android/Readme.md)


## Contributing

Any help testing the software, reporting or fixing bugs, reviewing pull requests
and recent changes, writing tests, or helping with outstanding issues is very welcome.
Implementing new features, or improving/refactoring the codebase, is of course
also welcome, but to avoid wasted effort, especially for larger changes,
we encourage discussing these on the issue tracker or IRC first.

Besides [GitHub](https://github.com/spesmilo/electrum),
most communication about Electrum development happens on IRC, in the
`#electrum` channel on Libera Chat. The easiest way to participate on IRC is
with the web client, [web.libera.chat](https://web.libera.chat/#electrum).
