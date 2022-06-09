# Running Electrum from source on macOS (development version)

## Prerequisites

- [brew](https://brew.sh/)
- python3
- git

## Main steps

### 1. Check out the code from GitHub:
```
$ git clone https://github.com/spesmilo/electrum.git
$ cd electrum
$ git submodule update --init
```

Run install (this should install most dependencies):
```
$ python3 -m pip install --user -e ".[crypto]"
```

### 2. Install libsecp256k1
```
$ brew install autoconf automake libtool coreutils
$ contrib/make_libsecp256k1.sh
```

### 3. Install PyQt5

On Intel-based (x86_64) Macs:
```
$ python3 -m pip install --user pyqt5
```

Re ARM-based Macs (Apple M1), there are no prebuilt wheels on PyPI.
As a workaround, we can install it from `brew`:
```
$ brew install pyqt5
$ echo 'export PATH="/opt/homebrew/opt/qt@5/bin:$PATH"' >> ~/.zshrc
$ echo 'export PATH="/opt/homebrew/opt/pyqt@5/5.15.4_1/bin:$PATH"' >> ~/.zshrc
$ source ~/.zshrc
```

### 4. Run electrum:
```
$ ./run_electrum
```
