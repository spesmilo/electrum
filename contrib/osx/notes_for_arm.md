# Notes on running Electrum from source on ARM-based Macs (Apple M1 OSX)

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

2. cryptography and will need to be manually installed. It will mention pycryptodomex, but prefer cryptography:

```
$ pip install cryptography
```

3. Install libsecp256k1

```
$ contrib/make_libsecp256k1.sh
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
>>> import PyQt5
```

5. Run electrum: 

```
$ ./run_electrum
```

