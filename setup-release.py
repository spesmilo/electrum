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

name = "Electrum ZCL"
mainscript = 'electrum-zcl'

plist = Plist.fromFile('Info.plist')
plist.update(dict(CFBundleIconFile='icons/electrum.icns'))


os.environ["REQUESTS_CA_BUNDLE"] = "cacert.pem"
shutil.copy(mainscript, mainscript + '.py')
mainscript += '.py'
extra_options = dict(
    setup_requires=['py2app'],
    app=[mainscript],
    packages=[
        'electrum-zcl',
        'electrum-zcl_gui',
        'electrum-zcl_gui.qt',
        'electrum-zcl_plugins',
        'electrum-zcl_plugins.audio_modem',
        'electrum-zcl_plugins.cosigner_pool',
        'electrum-zcl_plugins.email_requests',
        'electrum-zcl_plugins.greenaddress_instant',
        'electrum-zcl_plugins.hw_wallet',
        'electrum-zcl_plugins.keepkey',
        'electrum-zcl_plugins.labels',
        'electrum-zcl_plugins.ledger',
        'electrum-zcl_plugins.trezor',
        'electrum-zcl_plugins.digitalbitbox',
        'electrum-zcl_plugins.trustedcoin',
        'electrum-zcl_plugins.virtualkeyboard',

    ],
    package_dir={
        'electrum-zcl': 'lib',
        'electrum-zcl_gui': 'gui',
        'electrum-zcl_plugins': 'plugins'
    },
    data_files=[CERT_PATH],
    options=dict(py2app=dict(argv_emulation=False,
                             includes=['sip'],
                             packages=['lib', 'gui', 'plugins'],
                             iconfile='icons/electrum.icns',
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
