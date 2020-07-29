Electron-Cash-Satochip - Lightweight Bitcoin Cash client for the Satochip Hardware Wallet
==========================================================================================

::

  Licence: MIT Licence
  Author: The Electron Cash Developers; Satochip portions by Toporin
  Language: Python (>= 3.6)
  Homepage:

Introduction
============

This is a fork of Electron Cash modified for use with the Satochip Hardware Wallet. To use it, you need a device with the Satochip Javacard Applet installed.
If the wallet is not intialized yet, Electron Cash will perform the setup (you only need to do this once). During setup, a seed is created: this seed allows you to recover your wallet at anytime, so make sure to BACKUP THE SEED SECURELY! During setup, a PIN code is also created: this PIN allows to unlock th device to access your funds. If you try too many wrong PIN, your device will be locked indefinitely (it is 'bricked'). If you loose your PIN or brick your device, you can only recover your funds with the seed backup.

The Satochip wallet is currently in Beta, use with caution!You can use the software on the Bitcoin testnet using the --testnet option.
This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.

Rem: Electron Cash uses Python 3.x. In case of error, check first that you are not trying to run Electron Cash with Python 2.x or with Python 2.x libraries.

Development version (Windows 64bits)
=====================================

Install the latest python 3.6 release from https://www.python.org (https://www.python.org/downloads/release/python-368/)
(Caution: installing another release than 3.6 may cause incompatibility issues with pyscard)

Clone or download the code from GitHub.

Open a PowerShell command line in the Electron-Cash folder

In PowerShell, install the Electron-Cash dependencies::

    python -m pip install .

You may also ned to install Python3-pyqt5::

    python -m pip install pyqt5

Install pyscard from https://pyscard.sourceforge.io/
Pyscard is required to connect to the smartcard::

    python -m pip install pyscard

In case of error message, you may also install pyscard from the installer:
Download the .whl files from https://sourceforge.net/projects/pyscard/files/pyscard/pyscard%201.9.7/ and run::

    python -m pip install pyscard-1.9.7-cp36-cp36m-win_amd64.whl

In PowerShell, run Electron Cash on the testnet (-v allows for verbose output)::

    python .\electron-cash  -v --testnet


Development version (Ubuntu)
==============================
(Electron Cash requires Python 3.6, which should be installed by default on Ubuntu)
(If necessary, install pip: sudo apt-get install python3-pip)

Electron Cash is a pure python application. To use the
Qt interface, install the Qt dependencies::

    sudo apt-get install python3-pyqt5

Check out the code from GitHub::

    git clone https://github.com/Toporin/Electron-Cash-Satochip.git
    cd Electron-Cash-Satochip

In the Electron-Cash folder:

Run install (this should install dependencies)::

    python3 -m pip install .

Install pyscard (https://pyscard.sourceforge.io/)
Pyscard is required to connect to the smartcard::
    sudo apt-get install pcscd
    sudo apt-get install python3-pyscard
(For alternatives, see https://github.com/LudovicRousseau/pyscard/blob/master/INSTALL.md for more detailed installation instructions)


To run Electron Cash on the testnet use::
 python3 electron-cash  -v --testnet


Test suite
=============

To run the test suite, run::

    python -m unittest plugins.satochip.test_CardConnector

The test suite uses the following default PIN code: "12345678".
If you run the test suite after (or before) Electron Cash, you may block the card if the PIN used are not the same!
If the card is locked, you will have to reinstall the javacard applet on the card.
