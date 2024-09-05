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
$ python3 -m pip install --user -e ".[gui,crypto]"
```

### 2. Install libsecp256k1
```
$ brew install autoconf automake libtool coreutils
$ contrib/make_libsecp256k1.sh
```

### 3. Run electrum:
```
$ ./run_electrum
```
