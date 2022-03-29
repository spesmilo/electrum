# Notes on building Electrum on Apple M1 OSX 


1. Clone repository and build Electrum as usual:

```
$ git clone https://github.com/spesmilo/electrum.git
$ cd electrum
$ ./contrib/osx/make_osx
```

2. pycryptodomex and cryptography and will need to be manually installed:

```
$ pip install pycryptodomex
$ pip install cryptography
```

4. Manually install libsecp256k1 from source (https://github.com/bitcoin-core/secp256k1#build-steps) but with the following modifications: 

```
$ ./autogen.sh
$ ./configure --enable-module-recovery
$ make
$ make check  # run the test suite
$ sudo make install  # optional
```

5. To bypass the pyqt5 install issue, do the following:

```
$ brew install pyqt5
$ echo 'export PATH="/opt/homebrew/opt/qt@5/bin:$PATH"' >> ~/.zshrc
$ echo 'export PATH="/opt/homebrew/opt/pyqt@5/5.15.4_1/bin:$PATH"' >> ~/.zshrc
$ source ~/.zshrc
```

Finally, try it in python to ensure it works: 

```
$ python3
>> import PyQt5
```

6. Run electrum: 

```
$ ./run_electrum
```

