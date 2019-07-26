Satochip plugin for electrum
=================================================================================

::

  Licence: MIT Licence
  Author: Toporin
  Language: Python (>= 3.6)
  Homepage: https://github.com/Toporin/electrum-satochip

Introduction
============

This plugin allows to integrate the Satochip Hardware Wallet with Electrum. To use it, you need a device with the Satochip javacard applet installed (see https://github.com/Toporin/SatochipApplet).
If the wallet is not intialized yet, Electrum will perform the setup (you only need to do this once). During setup, a seed is created: this seed allows you to recover your wallet at anytime, so make sure to BACKUP THE SEED SECURELY! During setup, a PIN code is also created: this PIN allows to unlock th device to access your funds. If you try too many wrong PIN, your device will be locked indefinitely (it is 'bricked'). If you loose your PIN or brick your device, you can only recover your funds with the seed backup.

The Satochip wallet is currently in Beta, use with caution! In this phase, it is strongly recommended to use the software on the Bitcoin testnet first.
This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.

Rem: Electrum uses Python 3.x. In case of error, check first that you are not trying to run Electrum with Python 2.x or with Python 2.x libraries.

Development version (Windows 64bits)
=====================================

Install the latest python 3.6 release from https://www.python.org (https://www.python.org/downloads/release/python-368/)
(Caution: installing another release than 3.6 may cause incompatibility issues with pyscard)

Clone or download the code from GitHub.

Open a PowerShell command line in the electrum folder

In PowerShell, install the electrum dependencies::

    python -m pip install .   
    
You may also ned to install Python3-pyqt5::

    python -m pip install pyqt5
    
Install pyscard from https://pyscard.sourceforge.io/
Pyscard is required to connect to the smartcard::

    python -m pip install pyscard
    
In case of error message, you may also install pyscard from the installer:
Download the .whl files from https://sourceforge.net/projects/pyscard/files/pyscard/pyscard%201.9.7/ and run::

    python -m pip install pyscard-1.9.7-cp36-cp36m-win_amd64.whl

In PowerShell, run electrum on the testnet (-v allows for verbose output)::

    python .\run_electrum -v --testnet
    

Development version (Ubuntu)
==============================
(Electrum requires Python 3.6, which should be installed by default on Ubuntu)
(If necessary, install pip: sudo apt-get install python3-pip)

Electrum is a pure python application. To use the
Qt interface, install the Qt dependencies::

    sudo apt-get install python3-pyqt5

Check out the code from GitHub::
    
    git clone git://github.com/Toporin/electrum.git
    cd electrum
    
In the electrum folder:    
    
Run install (this should install dependencies)::

    python3 -m pip install .
    
Install pyscard (https://pyscard.sourceforge.io/)
Pyscard is required to connect to the smartcard:: 
    sudo apt-get install pcscd
    sudo apt-get install python3-pyscard
(For alternatives, see https://github.com/LudovicRousseau/pyscard/blob/master/INSTALL.md for more detailed installation instructions)

 
To run Electrum use::
 python3 electrum -v --testnet 
 
 
Test suite
=============
 
To run the test suite, run::

    python -m unittest electrum.plugins.satochip.test_CardConnector
 
The test suite uses the following default PIN code: "12345678".
If you run the test suite after (or before) electrum, you may block the card if the PIN used are not the same!
If the card is locked, you will have to reinstall the javacard applet on the card.

