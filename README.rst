Electrum - Lightweight Bitcoin client
=====================================

::

  Licence: MIT Licence
  Author: Thomas Voegtlin
  Language: Python
  Homepage: https://electrum.org/


.. image:: https://travis-ci.org/spesmilo/electrum.svg?branch=master
    :target: https://travis-ci.org/spesmilo/electrum
    :alt: Build Status





Getting started
===============

Electrum is a pure python application. However, if you want to use the
Qt interface, then you need to install the Qt dependencies::

    sudo apt-get install python-qt4

If you downloaded the official package (tar.gz), then you can run
Electrum from its root directory, without installing it on your
system; all the python dependencies are included in the 'packages'
directory. To run Electrum from its root directory, just do::

    ./electrum

If you cloned the git repository, then you need to compile extra files
before you can run Electrum. Read the next section, "Development
Version".



Development version
===================

Check out the code from Github::

    git clone git://github.com/spesmilo/electrum.git
    cd electrum

Run install (this should install dependencies)::

    python setup.py install

Compile the icons file for Qt::

    sudo apt-get install pyqt4-dev-tools
    pyrcc4 icons.qrc -o gui/qt/icons_rc.py

Compile the protobuf description file::

    sudo apt-get install protobuf-compiler
    protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto

Create translations::

    sudo apt-get install python-pycurl gettext
    ./contrib/make_locale



Install on Linux systems
========================

If you install Electrum on your system, you can run it from any
directory.

If you have pip, you can do::

    python setup.py sdist
    sudo pip install --pre dist/Electrum-2.0.tar.gz


If you don't have pip, install with::

    python setup.py sdist
    sudo python setup.py install



Creating Binaries
=================


In oder to creating binaries, you must create the 'packages' directory::

    ./contrib/make_packages

This directory contains the python dependencies used by Electrum.

Mac OS X
--------

    # On port based installs
    sudo python setup-release.py py2app

    # On brew installs
    ARCHFLAGS="-arch i386 -arch x86_64" sudo python setup-release.py py2app --includes sip

    sudo hdiutil create -fs HFS+ -volname "Electrum" -srcfolder dist/Electrum.app dist/electrum-VERSION-macosx.dmg


Windows
-------

see contrib/build-wine/README


Android
-------

see gui/kivy/Readme.txt
