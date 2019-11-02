Electron Cash - Lightweight Bitcoin Cash client
=====================================

::

  Licence: MIT Licence
  Author: Electron Cash Developers
  Language: Python
  Homepage: https://electroncash.org/


.. image:: https://d322cqt584bo4o.cloudfront.net/electron-cash/localized.svg
    :target: https://crowdin.com/project/electron-cash
    :alt: Help translate Electron Cash online





Getting started
===============

*Note: If running from source, Python 3.6 or above is required to run Electron Cash. If your system lacks Python 3.6,
you have other options, such as the* `binary releases <https://github.com/Electron-Cash/Electron-Cash/releases/>`_.

Electron Cash is a pure python application forked from Electrum. If you want to use the Qt interface, install the Qt dependencies::

    sudo apt-get install python3-pyqt5 python3-pyqt5.qtsvg

If you downloaded the official package (tar.gz), you can run
Electron Cash from its root directory (called Electrum), without installing it on your
system; all the python dependencies are included in the 'packages'
directory. To run Electron Cash from its root directory, just do::

    ./electron-cash

You can also install Electron Cash on your system, by running this command::

    sudo apt-get install python3-setuptools
    python3 setup.py install

This will download and install the Python dependencies used by
Electron Cash, instead of using the 'packages' directory.

If you cloned the git repository, you need to compile extra files
before you can run Electron Cash. Read the next section, "Development
Version".

Hardware Wallet - Ledger Nano S
-------------------------------

Electron Cash natively support Ledger Nano S hardware wallet. If you plan to use
you need an additional dependency, namely btchip. To install it run this command::

    sudo pip3 install btchip-python

If you still have problems connecting to your Nano S please have a look at this
`troubleshooting <https://support.ledger.com/hc/en-us/articles/115005165269-Fix-connection-issues>`_ section on Ledger website.


Development version
===================

Check your python version >= 3.6, and install pyqt5, as instructed above in the
`Getting started`_ section.

Check out the code from Github::

    git clone https://github.com/Electron-Cash/Electron-Cash
    cd Electron-Cash

Install the python dependencies::

    pip3 install -r contrib/requirements/requirements.txt --user

Then

Compile the protobuf description file::

    sudo apt-get install protobuf-compiler
    protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto

Create translations (optional)::

    sudo apt-get install python-requests gettext
    ./contrib/make_locale

Compile libsecp256k1 (optional, yet highly recommended)::

    sudo apt-get install libtool automake
    ./contrib/make_secp

For plugin development, see the `plugin documentation <plugins/README.rst>`_.

Running unit tests::

    pip install tox
    tox

Tox will take care of building a faux installation environment, and ensure that
the mapped import paths work correctly.

Creating Binaries
=================

Linux AppImage & Source Tarball
--------------

See `contrib/build-linux/README.md <contrib/build-linux/README.md>`_.

Mac OS X / macOS
--------

See `contrib/osx/ <contrib/osx/>`_.

Windows
-------

See `contrib/build-wine/ <contrib/build-wine>`_.

Android
-------

See `android/ <android/>`_.

iOS
-------

See `ios/ <ios/>`_.
