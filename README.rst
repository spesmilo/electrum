ZCL Electrum - Zclassic Electrum (Lite) Client
==============================================

Latest Release: https://github.com/z-classic/electrum-zcl/releases


Viewing & Sending from Z addresses is not yet supported on this wallet.


Know about your data directory::

    Linux + Mac: ~/.electrum-zcl/
    Windows: C:\Users\YourUserName\AppData\Roaming\Electrum-zcl\

    ~/.electrum-zcl/wallets/ has your wallet files - BACK UP THIS FOLDER

You can also use 'Export Private Keys' and 'Show Seed' from inside the application to write down and store your funds.

Please use the issue tracker for bug reports, feature requests, and other mission-critical information. It is actively monitored by the Zclassic development team. For general support, please visit our Discord: https://discord.gg/45NNrMJ

Development Version
===================

First, clone from Github::

    git clone https://github.com/z-classic/electrum-zcl.git
    cd electrum-zcl

For Mac:
--------

Using Homebrew::

    # Setup Homebrew
    ./setup-mac

    # Install Homebrew dependencies
    brew bundle

    # Install Python dependencies
    pip3 install -r requirements.txt

    # Build icons
    pyrcc5 icons.qrc -o gui/qt/icons_rc.py

    # Compile the protobuf description file
    protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto

    # Build .app, .dmg
    ./create-dmg.sh

    # Run the .app in dist/, or
    ./electrum-zcl

For Linux:
----------

Install Dependencies::

  sudo apt-get install python-pip pyqt5-dev-tools $(grep -vE "^\s*#" packages.txt  | tr "\n" " ")

  pip3 install -r requirements.txt

  #(Ubuntu with ledger wallet)
  #ln -s /lib/x86_64-linux-gnu/libudev.so.1 /lib/x86_64-linux-gnu/libudev.so

  # For yum installations (no apt-get), or for a clean python env, use Anaconda with Python 3:
  # https://poweruphosting.com/blog/install-anaconda-python-ubuntu-16-04/


Compile the icons file for Qt::

    pyrcc5 icons.qrc -o gui/qt/icons_rc.py

For the Linux app launcher (start menu) icon::

    sudo desktop-file-install electrum.desktop

Compile the protobuf description file::

    protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto

Create translations (optional)::

    ./contrib/make_locale

Run::

    ./electrum-zcl


For Linux with docker:
----------------------

Build the docker image::

    ./build-docker.sh

Run the docker image::

    ./run-docker.sh


Building Releases
=================


MacOS
------

Simply - ::

    ./setup-mac.sh

    sudo ./create-dmg.sh

Windows
-------

See `contrib/build-wine/README` file.


Android
-------

See `gui/kivy/Readme.txt` file.
UPSTREAM PATCH: https://github.com/spesmilo/electrum/blob/master/gui/kivy/Readme.md

---

To just create binaries, create the 'packages/' directory::

    ./contrib/make_packages

(This directory contains the Python dependencies used by Electrum-ZCL.)


ZCL Hints and Debug
===================

There are several useful scripts in::

    scripts

Here is a good initial check to determine whether things are working (should successfully validate chunks)::

    cd scripts
    python3 block_headers

--

The Zclassic Wiki is located at: https://github.com/z-classic/zclassic/wiki. Please use this as a reference and feel free to contribute.


Original Project Info
---------------------
::

  Forked from **spesmilo/electrum**: https://github.com/spesmilo/electrum

  Licence: MIT Licence
  Author: Thomas Voegtlin
  Language: Python (GUI: Qt, Kivy)
  Platforms: Windows, Mac, Linux, Android
  Homepage: https://electrum.org/


.. image:: https://travis-ci.org/spesmilo/electrum.svg?branch=master
    :target: https://travis-ci.org/spesmilo/electrum
    :alt: Build Status
.. image:: https://coveralls.io/repos/github/spesmilo/electrum/badge.svg?branch=master
    :target: https://coveralls.io/github/spesmilo/electrum?branch=master
    :alt: Test coverage statistics


---

The Zclassic CE Team

ZCL: t3eYEnoMmfUV65CZvPvV2mfAUnfFGoFbkJu
