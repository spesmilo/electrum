#!/usr/bin/python

# python setup.py sdist --format=zip,gztar

from distutils.core import setup
from lib.version import ELECTRUM_VERSION as version

setup(name = "Electrum",
    version = version,
    install_requires = ['slowaes','ecdsa'],
    package_dir = {'electrum': 'lib'},
    scripts= ['electrum'],
    py_modules = ['electrum.version','electrum.wallet','electrum.interface','electrum.gui','electrum.gui_qt','electrum.icons_rc','electrum.mnemonic','electrum.pyqrnative','electrum.bmp'],
    description = "Lightweight Bitcoin Wallet",
    author = "thomasv",
    license = "GNU GPLv3",
    url = "http://ecdsa/electrum",
    long_description = """Lightweight Bitcoin Wallet""" 
)
