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

Create translations (optional)::

    sudo apt-get install python-pycurl gettext
    ./contrib/make_locale
