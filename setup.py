#!/usr/bin/python

# python setup.py sdist --format=zip,gztar

from distutils.core import setup
from lib.version import ELECTRUM_VERSION as version
import os, sys
if sys.version_info[:3] < (2,6,0):
    print "Electrum requires Python version >= 2.6.0... exiting"
    sys.exit(1)
            

data_files=[
    ('/usr/share/applications/',['electrum.desktop']),
    ('/usr/share/app-install/icons/',['electrum.png'])
    ]

if not os.path.exists('locale'):
    os.mkdir('locale')

for lang in os.listdir('locale'):
    if os.path.exists('locale/%s/LC_MESSAGES/electrum.mo'%lang):
        data_files.append(  ('/usr/share/locale/%s/LC_MESSAGES'%lang, ['locale/%s/LC_MESSAGES/electrum.mo'%lang]) )

setup(name = "Electrum",
    version = version,
    install_requires = ['slowaes','ecdsa'],
    package_dir = {'electrum': 'lib'},
    scripts= ['electrum'],
    data_files = data_files,
    py_modules = ['electrum.version',
                  'electrum.wallet',
                  'electrum.interface',
                  'electrum.gui',
                  'electrum.gui_qt',
                  'electrum.icons_rc',
                  'electrum.mnemonic',
                  'electrum.pyqrnative',
                  'electrum.bmp',
                  'electrum.msqr',
                  'electrum.i18n'],
    description = "Lightweight Bitcoin Wallet",
    author = "thomasv",
    license = "GNU GPLv3",
    url = "http://ecdsa/electrum",
    long_description = """Lightweight Bitcoin Wallet""" 
)


