.. image:: https://travis-ci.org/Feathercoin-Foundation/electrum-ftc.svg?branch=3.0.6-ftc
    :target: https://travis-ci.org/Feathercoin-Foundation/electrum-ftc
    :alt: Build Status


electrum-ftc - Lightweight Feathercoin client
=====================================

electrum-ftc is a fork of the `Bitcoin Electrum wallet <https://electrum.org/>`_ adapted to work with Feathercoin.
All improvements which are not related to Feathercoin itself will be made directly in the
`upstream Electrum repository <https://github.com/spesmilo/electrum>`_.

Relevant changes to the Bitcoin Electrum wallet:

- Works with the Feathercoin specifics (address format, difficulty adjustment, NeoScrypt)
- All transactions are replace-by-fee transactions
- No hardware wallet support
- No support for Trustedcoin 2FA or GreenAddress
- No Android version


Getting started
===============

Windows
-------

The Windows builds come in three flavors:

1. *setup* - this will properly install Electrum-FTC on Windows including
   adding icons to the Desktop and Start Menu. The installed exe has the
   fastest startup time of all three flavors. Most users want to use this flavor.

2. *standalone* - this is an exe that does not need any installation. It
   will use the ``%APPDATA%`` folder to store settings and wallet data.

3. *portable* - this is an exe that does not need any installation. It will
   use the folder where the exe is located to store settings and wallet
   data. Therefore, it can be used on an USB pen drive to use Electrum-FTC
   on multiple computers - hence portable. This flavor is most interesting
   for testers who don't want to interfere with their existing installation
   of Electrum-FTC.

Download the latest version from our `release page <https://github.com/Feathercoin-Foundation/electrum-ftc/releases>`_.

Mac
---

Download the latest version from our `release page <https://github.com/Feathercoin-Foundation/electrum-ftc/releases>`_.

Linux
-----

First the dependencies need to be installed. For Ubuntu/Debian::

    sudo apt-get install git libssl-dev python3-pip python3-pyqt5 pyqt5-dev-tools

Then, install the current release of electrum-ftc::

    pip3 install git+https://https://github.com/Feathercoin-Foundation/electrum-ftc.git@current_release

Prepend ``sudo`` if you want to install electrum-ftc system-wide (not recommended).

The installation will populate your desktop environment's application menu
where it can be conveniently launched.


Development version
===================

Check out the code from Github::

    git clone https://github.com/Feathercoin-Foundation/electrum-ftc.git
    cd electrum-ftc

Run install (this should install dependencies)::

    sudo apt-get install libssl-dev python3-pyqt5 pyqt5-dev-tools
    python3 setup.py install

Compile the icons file for Qt::

    pyrcc5 icons.qrc -o gui/qt/icons_rc.py

Create translations (optional)::

    sudo apt-get install python-pycurl gettext
    ./contrib/make_locale
