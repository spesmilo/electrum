#!/usr/bin/env python3

# python setup.py sdist --format=zip,gztar

from setuptools import setup
from setuptools.command.install import install
from distutils import core
import os
import sys
import platform
import imp
import argparse

version = imp.load_source('version', 'lib/version.py')

if sys.version_info[:3] < (3, 4, 0):
    sys.exit("Error: Electrum requires Python version >= 3.4.0...")

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
        (os.path.join(usr_share, 'applications/'), ['electrum-ftc.desktop']),
        (os.path.join(usr_share, 'pixmaps/'), ['icons/electrum.png'])
    ]


class InstallCommand(install):
    def run(self):
        if platform.system() is 'Windows':
            core.run_setup('neoscrypt_module/setup.py', ['build', '--compiler=mingw32'])
        core.run_setup('neoscrypt_module/setup.py', ['install'])
        install.run(self)

setup(
    name="Electrum-FTC",
    version=version.ELECTRUM_VERSION,
    cmdclass={'install': InstallCommand},
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
        'scrypt',
    ],
    packages=[
        'electrum_ftc',
        'electrum_ftc_gui',
        'electrum_ftc_gui.qt',
        'electrum_ftc_plugins',
        'electrum_ftc_plugins.audio_modem',
        'electrum_ftc_plugins.cosigner_pool',
        'electrum_ftc_plugins.email_requests',
        'electrum_ftc_plugins.hw_wallet',
        'electrum_ftc_plugins.keepkey',
        'electrum_ftc_plugins.labels',
        'electrum_ftc_plugins.ledger',
        'electrum_ftc_plugins.trezor',
        'electrum_ftc_plugins.digitalbitbox',
        'electrum_ftc_plugins.virtualkeyboard',
    ],
    package_dir={
        'electrum_ftc': 'lib',
        'electrum_ftc_gui': 'gui',
        'electrum_ftc_plugins': 'plugins',
    },
    package_data={
        'electrum_ftc': [
            'servers.json',
            'servers_testnet.json',
            'currencies.json',
            'www/index.html',
            'wordlist/*.txt',
            'locale/*/LC_MESSAGES/electrum.mo',
        ]
    },
    scripts=['electrum'],
    data_files=data_files,
    description="Lightweight Feathercoin Wallet",
    author="Thomas Voegtlin; Feathercoin Development Foundation",
    author_email="thomasv@electrum.org; info@feathercoin.foundation",
    license="MIT Licence",
    url="https://electrum.org",
    long_description="""Lightweight Feathercoin Wallet"""
)
