# Notes on building Electrum on Apple M1 OSX (ARM)

Development version (git clone)

1. Check out the code from GitHub:

```
$ git clone https://github.com/spesmilo/electrum.git
$ cd electrum
$ git submodule update --init
```

Run install (this should install dependencies):
```
python3 -m pip install --user -e .
```

2. pycryptodomex and cryptography and will need to be manually installed:

```
$ pip install pycryptodomex
$ pip install cryptography
```

3. Manually install libsecp256k1 from source (https://github.com/bitcoin-core/secp256k1#build-steps) but with the following modifications: 

```
$ ./autogen.sh
$ ./configure --enable-module-recovery
$ make
$ make check  # run the test suite
$ sudo make install  # optional
```

4. `pip install pyqt5` will work on intel x86, however for M1, to bypass pyqt5 install issue, do the following:

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

5. Run electrum: 

```
$ ./run_electrum
```

