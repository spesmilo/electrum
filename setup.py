#!/usr/bin/env python2

# python setup.py sdist --format=zip,gztar

from setuptools import setup
import os
import sys
import platform
import imp

version = imp.load_source('version', 'lib/version.py')

if sys.version_info[:3] < (2, 7, 0):
    sys.exit("Error: Electrum requires Python version >= 2.7.0...")

data_files = []

if platform.system() in ['Linux', 'FreeBSD', 'DragonFly']:
    usr_share = os.path.join(sys.prefix, "share")
    data_files += [
        (os.path.join(usr_share, 'applications/'), ['electrum-ltc.desktop']),
        (os.path.join(usr_share, 'pixmaps/'), ['icons/electrum-ltc.png'])
    ]

setup(
    name="Electrum-LTC",
    version=version.ELECTRUM_VERSION,
    install_requires=[
        'slowaes>=0.1a1',
        'ecdsa>=0.9',
        'pbkdf2',
        'requests',
        'qrcode',
        'ltc_scrypt',
        'protobuf',
        'dnspython',
    ],
    packages=[
        'electrum_ltc',
        'electrum_ltc_gui',
        'electrum_ltc_gui.qt',
        'electrum_ltc_plugins',
        'electrum_ltc_plugins.audio_modem',
        'electrum_ltc_plugins.cosigner_pool',
        'electrum_ltc_plugins.email_requests',
        'electrum_ltc_plugins.exchange_rate',
        'electrum_ltc_plugins.keepkey',
        'electrum_ltc_plugins.labels',
        'electrum_ltc_plugins.ledger',
        'electrum_ltc_plugins.plot',
        'electrum_ltc_plugins.trezor',
        'electrum_ltc_plugins.virtualkeyboard',
    ],
    package_dir={
        'electrum_ltc': 'lib',
        'electrum_ltc_gui': 'gui',
        'electrum_ltc_plugins': 'plugins',
    },
    package_data={
        'electrum_ltc': [
            'www/index.html',
            'wordlist/*.txt',
            'locale/*/LC_MESSAGES/electrum.mo',
        ]
    },
    scripts=['electrum-ltc'],
    data_files=data_files,
    description="Lightweight Litecoin Wallet",
    author="Thomas Voegtlin",
    author_email="thomasv@electrum.org",
    license="GNU GPLv3",
    url="http://electrum-ltc.org",
    long_description="""Lightweight Litecoin Wallet"""
)
