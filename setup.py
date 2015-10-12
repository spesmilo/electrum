#!/usr/bin/python

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
if platform.system() in [ 'Linux', 'FreeBSD', 'DragonFly']:
    usr_share = os.path.join(sys.prefix, "share")
    data_files += [
        (os.path.join(usr_share, 'applications/'), ['electrum-grs.desktop']),
        (os.path.join(usr_share, 'pixmaps/'), ['icons/electrum-grs.png'])
    ]


setup(
    name="Electrum-grs",
    version=version.ELECTRUM_VERSION,
    install_requires=[
        'slowaes>=0.1a1',
        'ecdsa>=0.9',
        'pbkdf2',
        'requests',
        'qrcode',
        'protobuf',
        'dnspython',
        'coinhash>=1.1.5'
    ],
    package_dir={
        'electrum_grs': 'lib',
        'electrum_grs_gui': 'gui',
        'electrum_grs_plugins': 'plugins',
    },
    packages=['electrum_grs','electrum_grs_gui','electrum_grs_gui.qt','electrum_grs_plugins'],
    package_data={
        'electrum_grs': [
            'www/index.html',
            'wordlist/*.txt',
            'locale/*/LC_MESSAGES/electrum.mo',
        ],
        'electrum_grs_gui': [
            "qt/themes/cleanlook/name.cfg",
            "qt/themes/cleanlook/style.css",
            "qt/themes/sahara/name.cfg",
            "qt/themes/sahara/style.css",
            "qt/themes/dark/name.cfg",
            "qt/themes/dark/style.css",
        ]
    },
    scripts=['electrum-grs'],
    data_files=data_files,
    description="Lightweight Groestlcoin Wallet",
    author="Thomas Voegtlin",
    author_email="thomasv@electrum.org",
    license="GNU GPLv3",
    url="https://electrum.org",
    long_description="""Lightweight Groestlcoin Wallet"""
)
