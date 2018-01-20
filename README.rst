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

    git clone git://github.com/spesmilo/electrum.git
    cd electrum

For Mac:
--------

Using Homebrew::

    # Install Homebrew
		/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

		# (Optionally)
		sudo chown -R "$USER":admin /usr/local
		sudo chown -R "$USER":admin /Library/Caches/Homebrew

    # Install python3
		brew install python3
		brew link python3
		brew postinstall python3

		# Python setuptools
		curl https://bootstrap.pypa.io/ez_setup.py -o - | python3

    # Install pyqt5
		pip3 install pyqt5

		# Setup
		python3 setup.py install
		pyrcc5 icons.qrc -o gui/qt/icons_rc.py

		# Run
		./electrum

Alternatively, copy the generated `build/scripts-3.6/electrum` to the main directory::

    cp -f build/scripts-3.6/electrum electrum-mac
    ./electrum-mac


For Linux:
----------

Install Dependencies::

    sudo apt-get install python3-pyqt5
    sudo pip2 install pyblake2

    sudo apt-get install python3-setuptools
    python3 setup.py install

Compile the icons file for QT::

    sudo apt-get install pyqt5-dev-tools
    pyrcc5 icons.qrc -o gui/qt/icons_rc.py

For the linux app launcher (start menu) icon::

    sudo desktop-file-install electrum.desktop

Compile the protobuf description file::

    sudo apt-get install protobuf-compiler
    protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto

Create translations (optional)::

    sudo apt-get install python-requests gettext
    ./contrib/make_locale

Run::
    
    ./electrum



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

    `~/.electrum-zcl/wallets/` has your wallet files - this folder can be backed up.

    `~/.electrum-zcl/config` has your Electrum connection object.


=================


To create binaries, create the 'packages' directory::

    ./contrib/make_packages

This directory contains the python dependencies used by Electrum.

Mac OS X / macOS
----------------

::
    
    # On MacPorts installs: 
    sudo python3 setup-release.py py2app
    
    # On Homebrew installs: 
    ARCHFLAGS="-arch i386 -arch x86_64" sudo python3 setup-release.py py2app --includes sip
    
    sudo hdiutil create -fs HFS+ -volname "Electrum" -srcfolder dist/Electrum.app dist/electrum-VERSION-macosx.dmg

Windows
-------

See `contrib/build-wine/README` file.


Android
-------

See `gui/kivy/Readme.txt` file.

