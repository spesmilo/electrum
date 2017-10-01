#!/usr/bin/env python3

# python setup.py sdist --format=zip,gztar

from setuptools import setup
import os
import sys
import platform
import imp
import argparse

version = imp.load_source('version', 'lib/version.py')

if sys.version_info[:3] < (3, 4, 0):
    sys.exit("Error: Electron Cash requires Python version >= 3.4.0...")

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
        (os.path.join(usr_share, 'applications/'), ['electron.desktop']),
        (os.path.join(usr_share, 'pixmaps/'), ['icons/electron.png'])
    ]

setup(
    name="Electron Cash",
    version=version.ELECTRUM_VERSION,
    install_requires=[
        'pyaes>=0.1a1',
        'ecdsa>=0.9',
        'pbkdf2',
        'requests',
        'qrcode',
        'protobuf',
        'dnspython',
        'jsonrpclib-pelix',
        'PySocks>=1.6.6',
    ],
    packages=[
        'electroncash',
        'electroncash_gui',
        'electroncash_gui.qt',
        'electroncash_plugins',
        'electroncash_plugins.audio_modem',
        'electroncash_plugins.cosigner_pool',
        'electroncash_plugins.email_requests',
        'electroncash_plugins.greenaddress_instant',
        'electroncash_plugins.hw_wallet',
        'electroncash_plugins.keepkey',
        'electroncash_plugins.labels',
        'electroncash_plugins.ledger',
        'electroncash_plugins.trezor',
        'electroncash_plugins.digitalbitbox',
        'electroncash_plugins.virtualkeyboard',
    ],
    package_dir={
        'electroncash': 'lib',
        'electroncash_gui': 'gui',
        'electroncash_plugins': 'plugins',
    },
    package_data={
        'electroncash': [
            'servers.json',
            'servers_testnet.json',
            'currencies.json',
            'www/index.html',
            'wordlist/*.txt',
            'locale/*/LC_MESSAGES/electrum.mo',
        ]
    },
    scripts=['electron-cash'],
    data_files=data_files,
    description="Lightweight Bitcoin Cash Wallet",
    author="Jonald Fyookball",
    author_email="jonf@electroncash.org",
    license="MIT Licence",
    url="http://electroncash.org",
    long_description="""Lightweight Bitcoin Cash Wallet"""
)
