# Notes on running Electrum from source on ARM-based Macs (Apple M1 OSX)

Development version (git clone)

1. Check out the code from GitHub:

```
$ git clone https://github.com/spesmilo/electrum.git
$ cd electrum
$ git submodule update --init
```

Run install (this should install most dependencies):
```
$ python3 -m pip install --user -e ".[crypto]"
```

2. Install libsecp256k1

```
$ contrib/make_libsecp256k1.sh
```

3. `pip install pyqt5` would work on intel x86, however there are no prebuilt wheels on PyPI for M1.
As a workaround, we can install it from brew:

```
$ brew install pyqt5
$ echo 'export PATH="/opt/homebrew/opt/qt@5/bin:$PATH"' >> ~/.zshrc
$ echo 'export PATH="/opt/homebrew/opt/pyqt@5/5.15.4_1/bin:$PATH"' >> ~/.zshrc
$ source ~/.zshrc
```

Try it in python to ensure it works: 

```
$ python3
>>> import PyQt5
```

4. Run electrum: 

```
$ ./run_electrum
```

