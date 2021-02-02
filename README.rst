ELCASH Wallet - Lightweight Electric Cash client
================================================

::

  Licence: MIT Licence
  Language: Python (>= 3.6)
  Homepage: https://electriccash.global/


Getting started
===============

(*If you've come here looking to simply run ELCASH Wallet,* `you may download it here`_.)

.. _you may download it here: https://electriccash.global/#download

ELCASH Wallet itself is pure Python, and so are most of the required dependencies,
but not everything. The following sections describe how to run from source, but here
is a TL;DR::

    sudo apt-get install libsecp256k1-0
    python3 -m pip install --user .[gui,crypto]


Not pure-python dependencies
----------------------------

If you want to use the Qt interface, install the Qt dependencies::

    sudo apt-get install python3-pyqt5

For elliptic curve operations, `libsecp256k1`_ is a required dependency::

    sudo apt-get install libsecp256k1-0

Alternatively, when running from a cloned repository, a script is provided to build
libsecp256k1 yourself::

    sudo apt-get install automake libtool
    ./contrib/make_libsecp256k1.sh

Due to the need for fast symmetric ciphers, `cryptography`_ is required.
Install from your package manager (or from pip)::

    sudo apt-get install python3-cryptography



.. _libsecp256k1: https://github.com/bitcoin-core/secp256k1
.. _pycryptodomex: https://github.com/Legrandin/pycryptodome
.. _cryptography: https://github.com/pyca/cryptography

Running from tar.gz
-------------------

If you downloaded the official package (tar.gz), you can run
ELCASH Wallet from its root directory without installing it on your
system; all the pure python dependencies are included in the 'packages'
directory. To run ELCASH Wallet from its root directory, just do::

    ./run_electrum

You can also install ELCASH Wallet on your system, by running this command::

    sudo apt-get install python3-setuptools python3-pip
    python3 -m pip install --user .

This will download and install the Python dependencies used by
ELCASH Wallet instead of using the 'packages' directory.
It will also place an executable named :code:`elcash-wallet` in :code:`~/.local/bin`,
so make sure that is on your :code:`PATH` variable.


Development version (git clone)
-------------------------------

Check out the code from GitHub::

    git clone https://github.com/electric-cash/elcash-wallet.git
    cd elcash-wallet
    git submodule update --init

Run install (this should install dependencies)::

    python3 -m pip install --user -e .


Finally, to start ELCASH Wallet::

    ./run_electrum



Creating Binaries
=================

Linux (tarball)
---------------

See :code:`contrib/build-linux/sdist/README.md`.


Linux (AppImage)
----------------

See :code:`contrib/build-linux/appimage/README.md`.



Windows
-------

See :code:`contrib/build-wine/README.md`.
