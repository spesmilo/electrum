"""
py2app build script for Electrum Bitcoin Private

Usage (Mac OS X):
     python setup.py py2app
"""

from setuptools import setup
from plistlib import Plist
import requests
import os
import shutil

from lib.version import ELECTRUM_VERSION as version

CERT_PATH = requests.certs.where()

name = "Electrum"
mainscript = 'electrum'

plist = Plist.fromFile('Info.plist')
plist.update(dict(CFBundleIconFile='electrum.icns'))


os.environ["REQUESTS_CA_BUNDLE"] = "cacert.pem"
shutil.copy(mainscript, mainscript + '.py')
mainscript += '.py'
extra_options = dict(
    setup_requires=['py2app'],
    app=[mainscript],
    packages=[
        'electrum',
        'electrum_gui',
        'electrum_gui.qt',
        'electrum_plugins',
        'electrum_plugins.audio_modem',
        'electrum_plugins.cosigner_pool',
        'electrum_plugins.email_requests',
        'electrum_plugins.greenaddress_instant',
        'electrum_plugins.hw_wallet',
        'electrum_plugins.keepkey',
        'electrum_plugins.labels',
        'electrum_plugins.ledger',
        'electrum_plugins.trezor',
        'electrum_plugins.digitalbitbox',
        'electrum_plugins.trustedcoin',
        'electrum_plugins.virtualkeyboard',

    ],
    package_dir={
        'electrum': 'lib',
        'electrum_gui': 'gui',
        'electrum_plugins': 'plugins'
    },
    data_files=[CERT_PATH],
    options=dict(py2app=dict(argv_emulation=False,
                             includes=['sip'],
                             packages=['lib', 'gui', 'plugins'],
                             iconfile='electrum.icns',
                             plist=plist,
                             resources=["icons"])),
)

setup(
    name=name,
    version=version,
    **extra_options
)

# Remove the copied py file
os.remove(mainscript)
