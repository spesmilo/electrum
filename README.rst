Electrum-GRS - lightweight Groestlcoin client
=====================================

::

  Licence: GNU GPL v3
  Author: Groestlcoin Developers
  Language: Python
  Homepage: https://groestlcoin.org/


.. image:: https://travis-ci.org/spesmilo/electrum.svg?branch=master
    :target: https://travis-ci.org/spesmilo/electrum
    :alt: Build Status


1. GETTING STARTED
------------------

To run Electrum-grs from this directory, just do::

    ./electrum-grs

If you install Electrum on your system, you can run it from any
directory.

    python setup.py sdist
    sudo python setup.py install

2. HOW OFFICIAL PACKAGES ARE CREATED
------------------------------------

On Linux/Windows::

    pyrcc4 icons.qrc -o gui/qt/icons_rc.py
    python setup.py sdist --format=zip,gztar

On Mac OS X::

    # On port based installs
    sudo python setup-release.py py2app

    # On brew installs
    ARCHFLAGS="-arch i386 -arch x86_64" sudo python setup-release.py py2app --includes sip

    sudo hdiutil create -fs HFS+ -volname "Electrum-GRS" -srcfolder dist/Electrum.-grsapp dist/electrum-VERSION-macosx.dmg
