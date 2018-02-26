.. image:: https://travis-ci.org/Feathercoin-Foundation/electrum-ftc.svg?branch=3.0.6-ftc
    :target: https://travis-ci.org/Feathercoin-Foundation/electrum-ftc
    :alt: Build Status


electrum-ftc - Lightweight Feathercoin client
=====================================

electrum-ftc is a fork of the Bitcoin Electrum wallet (https://electrum.org/) adapted to work with Feathercoin.
All improvements which are not related to Feathercoin itself will be made directly in the upstream Electrum repository (https://github.com/spesmilo/electrum).

Relevant changes to the Bitcoin Electrum wallet:

- Works with the Feathercoin specifics (address format, difficulty adjustment, NeoScrypt)
- All transactions are replace-by-fee transactions
- bech32 is the only address format (all addresses start with fc1)
- No hardware wallet support
- No support for Trustedcoin 2FA or GreenAddress
- No Android version
- Pipenv for dependency management

Below you can find the original README from (Bitcoin) Electrum.


Electrum - Lightweight Bitcoin client
=====================================

::

  Licence: MIT Licence
  Author: Thomas Voegtlin
  Language: Python
  Homepage: https://electrum.org/




Getting started
===============

Electrum is a pure python application. If you want to use the
Qt interface, install the Qt dependencies::

    sudo apt-get install python3-pyqt5

If you downloaded the official package (tar.gz), you can run
Electrum from its root directory, without installing it on your
system; all the python dependencies are included in the 'packages'
directory. To run Electrum from its root directory, just do::

    ./electrum

You can also install Electrum on your system, by running this command::

    sudo apt-get install python3-setuptools
    python3 setup.py install

This will download and install the Python dependencies used by
Electrum, instead of using the 'packages' directory.

If you cloned the git repository, you need to compile extra files
before you can run Electrum. Read the next section, "Development
Version".



Development version
===================

Check out the code from Github::

    git clone git://github.com/spesmilo/electrum.git
    cd electrum

Run install (this should install dependencies)::

    python3 setup.py install

Compile the icons file for Qt::

    sudo apt-get install pyqt5-dev-tools
    pyrcc5 icons.qrc -o gui/qt/icons_rc.py

Compile the protobuf description file::

    sudo apt-get install protobuf-compiler
    protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto

Create translations (optional)::

    sudo apt-get install python-pycurl gettext
    ./contrib/make_locale




Creating Binaries
=================


To create binaries, create the 'packages' directory::

    ./contrib/make_packages

This directory contains the python dependencies used by Electrum.

Mac OS X / macOS
--------

::

    # On MacPorts installs: 
    sudo python3 setup-release.py py2app
    
    # On Homebrew installs: 
    ARCHFLAGS="-arch i386 -arch x86_64" sudo python3 setup-release.py py2app --includes sip
    
    sudo hdiutil create -fs HFS+ -volname "Electrum" -srcfolder dist/Electrum.app dist/electrum-VERSION-macosx.dmg

Windows
-------

See `contrib/build-wine/README` file.
