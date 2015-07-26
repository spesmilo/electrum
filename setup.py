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
        (os.path.join(usr_share, 'applications/'), ['electrum.desktop']),
        (os.path.join(usr_share, 'pixmaps/'), ['icons/electrum.png'])
    ]


setup(
    name="Electrum",
    version=version.ELECTRUM_VERSION,
    install_requires=[
        'pycrypto',
        'slowaes>=0.1a1',
        'ecdsa>=0.9',
        'pbkdf2',
        'requests',
        'qrcode',
        'protobuf',
        'tlslite',
        'dnspython',
    ],
    package_dir={
        'electrum': 'lib',
        'electrum_gui': 'gui',
        'electrum_plugins': 'plugins',
    },
    packages=['electrum','electrum_gui','electrum_gui.qt','electrum_plugins'],
    package_data={
        'electrum': [
            'www/index.html',
            'wordlist/*.txt',
            'locale/*/LC_MESSAGES/electrum.mo',
        ],
        'electrum_gui': [
            "qt/themes/cleanlook/name.cfg",
            "qt/themes/cleanlook/style.css",
            "qt/themes/sahara/name.cfg",
            "qt/themes/sahara/style.css",
            "qt/themes/dark/name.cfg",
            "qt/themes/dark/style.css",
        ]
    },
    scripts=['electrum'],
    data_files=data_files,
    description="Lightweight Bitcoin Wallet",
    author="Thomas Voegtlin",
    author_email="thomasv@electrum.org",
    license="GNU GPLv3",
    url="https://electrum.org",
    long_description="""Lightweight Bitcoin Wallet"""
)
