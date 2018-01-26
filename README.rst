ZCL Electrum - Lightweight Zclassic Client
==========================================

Forked from **spesmilo/electrum**: https://github.com/spesmilo/electrum

Original Project Info
---------------------
::

  Licence: MIT Licence
  Author: Thomas Voegtlin
  Language: Python
  Homepage: https://electrum.org/


.. image:: https://travis-ci.org/spesmilo/electrum.svg?branch=master
    :target: https://travis-ci.org/spesmilo/electrum
    :alt: Build Status
.. image:: https://coveralls.io/repos/github/spesmilo/electrum/badge.svg?branch=master
    :target: https://coveralls.io/github/spesmilo/electrum?branch=master
    :alt: Test coverage statistics



Getting started
===============

Electrum is a pure python application. If you want to use the
Qt interface, install the Qt dependencies.


If you downloaded the official package (tar.gz), you can run
Electrum from its root directory, without installing it on your
system; all the python dependencies are included in the 'packages'
directory. To run Electrum from its root directory, just do::

    ./electrum


If you cloned the git repository, you need to compile extra files
before you can run Electrum. Read the next section, "Development
Version".



Development version
===================

Check out the code from Github::

    git clone git://github.com/BTCP-community/electrum-zcl.git
    cd electrum-zcl

For Mac:
--------

Using Homebrew::

    # Setup Homebrew
    sh ./setup-mac.sh

    # Install Homebrew dependencies
    brew bundle

    # Install Python dependencies
    pip3 install -r requirements.txt

    # Build icons
		pyrcc5 icons.qrc -o gui/qt/icons_rc.py

    # Compile the protobuf description file
    protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto

    # Run
		./electrum

`(Alternatively, copy the generated "build/scripts-3.6/electrum" to the main directory)`::

    cp -f build/scripts-3.6/electrum electrum-mac
    ./electrum-mac


For Linux:
----------

Install Dependencies::

  sudo apt-get install $(grep -vE "^\s*#" packages.txt  | tr "\n" " ")

  pip install -r requirement.txt

  (Ubuntu with ledger wallet)
  ln -s /lib/x86_64-linux-gnu/libudev.so.1 /lib/x86_64-linux-gnu/libudev.so


Compile the icons file for Qt::

    pyrcc5 icons.qrc -o gui/qt/icons_rc.py

For the Linux app launcher (start menu) icon::

    sudo desktop-file-install electrum.desktop

Compile the protobuf description file::

    protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto

Create translations (optional)::
    ./contrib/make_locale

Run::

    ./electrum




Building Releases
=================


MacOS
------

Simply - ::

    sh ./setup-mac.sh

    sudo sh ./install-mac.sh

Windows
-------

See `contrib/build-wine/README` file.


Android
-------

See `gui/kivy/Readme.txt` file.

---

To just create binaries, create the 'packages/' directory::

    ./contrib/make_packages

(This directory contains the Python dependencies used by Electrum.)


ZCL Hints and Debug
===================

There are several useful scripts in::

    scripts

This is a good initial check to determine whether things are working.::

    cd scripts
    python3 block_headers

It should run, validating chunks without error.

Also be sure to check out:::

    ~/.electrum-zcl/

    ~/.electrum-zcl/wallets/ has your wallet files - ** back up this folder **

    ~/.electrum-zcl/config has your Electrum connection object.


---

The Zclassic Team
