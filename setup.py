#!/usr/bin/env python2

# python setup.py sdist --format=zip,gztar

from setuptools import setup
import os
import sys
import platform
import imp
import argparse

version = imp.load_source('version', 'lib/version.py')

if sys.version_info[:3] < (2, 7, 0):
    sys.exit("Error: Electrum requires Python version >= 2.7.0...")

data_files = []

if platform.system() in ['Linux', 'FreeBSD', 'DragonFly']:
    parser = argparse.ArgumentParser()
    parser.add_argument('--root=', dest='root_path', metavar='dir', default='/')
    opts, _ = parser.parse_known_args(sys.argv[1:])
    usr_share = os.path.join(sys.prefix, "share")
    if not os.access(opts.root_path + usr_share, os.W_OK) and \
       not os.access(opts.root_path, os.W_OK):
        if 'XDG_DATA_HOME' in os.environ.keys():
            usr_share = os.environ['XDG_DATA_HOME']
        else:
            usr_share = os.path.expanduser('~/.local/share')
    data_files += [
        (os.path.join(usr_share, 'applications/'), ['electrum-grs.desktop']),
        (os.path.join(usr_share, 'pixmaps/'), ['icons/electrum-grs.png'])
    ]

setup(
    name="Electrum-grs",
    version=version.ELECTRUM_VERSION,
    install_requires=[
        'pyaes',
        'ecdsa>=0.9',
        'pbkdf2',
        'requests',
        'qrcode',
        'protobuf',
        'dnspython',
        'jsonrpclib',
        'PySocks>=1.6.6',
        'coinhash>=1.1.5',
    ],
    dependency_links=[
        "git+https://github.com/mazaclub/python-trezor#egg=trezor",
    ],
    packages=[
        'electrum_grs',
        'electrum_grs_gui',
        'electrum_grs_gui.qt',
        'electrum_grs_plugins',
        'electrum_grs_plugins.audio_modem',
        'electrum_grs_plugins.cosigner_pool',
        'electrum_grs_plugins.email_requests',
        'electrum_grs_plugins.greenaddress_instant',
        'electrum_grs_plugins.hw_wallet',
        'electrum_grs_plugins.keepkey',
        'electrum_grs_plugins.labels',
        'electrum_grs_plugins.ledger',
        'electrum_grs_plugins.trezor',
        'electrum_grs_plugins.digitalbitbox',
        'electrum_grs_plugins.trustedcoin',
        'electrum_grs_plugins.virtualkeyboard',
    ],
    package_dir={
        'electrum_grs': 'lib',
        'electrum_grs_gui': 'gui',
        'electrum_grs_plugins': 'plugins',
    },
    package_data={
        'electrum_grs': [
            'currencies.json',
            'www/index.html',
            'wordlist/*.txt',
            'locale/*/LC_MESSAGES/electrum.mo',
        ]
    },
    scripts=['electrum-grs'],
    data_files=data_files,
    description="Lightweight Groestlcoin Wallet",
    author="Thomas Voegtlin",
    author_email="thomasv@electrum.org",
    license="MIT Licence",
    url="https://electrum.org",
    long_description="""Lightweight Groestlcoin Wallet"""
)
