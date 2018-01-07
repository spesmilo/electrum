Electron Cash - Lightweight Bitcoin Cash client
=====================================

::

  Licence: MIT Licence
  Author: Jonald Fyookball
  Language: Python
  Homepage: https://electroncash.org/




Getting started
===============

Electron Cash is a pure python application forked from Electrum. If you want to use the
Qt interface, install the Qt dependencies::

    sudo apt-get install python3-pyqt5

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



Development version
===================

Check out the code from Github::

    git clone git://github.com/fyookball/electrum.git
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

    sudo apt-get install python-requests gettext
    ./contrib/make_locale




Creating Binaries
=================


To create binaries, create the 'packages' directory::

    ./contrib/make_packages

This directory contains the python dependencies used by Electron Cash.

Mac OS X / macOS
--------

Requires python3.5+, pyqt5, protoc, gettext, pycurl, pyqt5-devtools, and possibly other packages. These instructions and support scripts presume you are using MacPorts. Brew-based building is left as an exercise for the reader. ;)

Compile the icons file for Qt (make sure pyrcc5 is installed)::

    pyrcc5 icons.qrc -o gui/qt/icons_rc.py

Compile the protobuf description file (make sure protoc is installed)::

    protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto

Create translations (optional)::

    ./contrib/make_locale

Create the 'packages' directory::

    ./contrib/make_packages

    ln -s contrib/packages packages

Now, you run can py2app (if it complains about missing python packages, use pip to install packages listed in contrib/requirements_osx.txt)::

    python setup-release.py py2app

Now, you'll have a dist/Electron-Cash.app, but it won't quite work.  You need to do some crazy magic to get python to see the files properly. Fortunately for you, I already went to the trouble to figure out this magic, and it's embodied in the fix_libs_osx.sh script. Run this script::

    contrib/fix_libs_osx.sh

Now, try to run it.  If it doesn't run, create an issue in github.  If it does, great! 

And finally, optionally create a .dmg...

    hdiutil create -fs HFS+ -volname "Electron-Cash" -srcfolder dist/Electron-Cash.app dist/electron-cash-VERSION-macosx.dmg

Windows
-------

See `contrib/build-wine/README` file.


Android
-------

See `gui/kivy/Readme.txt` file.
