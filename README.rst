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

    git clone git://github.com/spesmilo/electrum.git
    cd electrum

Run install (this should install dependencies)::

    python3 setup.py install

Compile the icons file for Qt::

    sudo apt-get install pyqt5-dev-tools
    pyrcc5 icons.qrc -o gui/qt/icons_rc.py

Create translations (optional)::

    sudo apt-get install python-pycurl gettext
    ./contrib/make_locale
