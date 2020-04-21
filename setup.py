#!/usr/bin/env python3

# python setup.py sdist --format=zip,gztar

from setuptools import setup, find_packages
import os
import sys
import platform
import imp
import argparse

with open('contrib/requirements/requirements.txt') as f:
    requirements = f.read().splitlines()

with open('contrib/requirements/requirements-hw.txt') as f:
    requirements_hw = f.read().splitlines()

version = imp.load_source('version', 'electrum/version.py')

if sys.version_info[:3] < (3, 4, 0):
    sys.exit("Error: Electrum requires Python version >= 3.4.0...")

data_files = []

if platform.system() in ['Linux', 'FreeBSD', 'DragonFly']:
    parser = argparse.ArgumentParser()
    parser.add_argument('--root=', dest='root_path', metavar='dir', default='/')
    opts, _ = parser.parse_known_args(sys.argv[1:])
    usr_share = os.path.join(sys.prefix, "share")
    icons_dirname = 'pixmaps'
    if not os.access(opts.root_path + usr_share, os.W_OK) and \
       not os.access(opts.root_path, os.W_OK):
        icons_dirname = 'icons'
        if 'XDG_DATA_HOME' in os.environ.keys():
            usr_share = os.environ['XDG_DATA_HOME']
        else:
            usr_share = os.path.expanduser('~/.local/share')
    data_files += [
        (os.path.join(usr_share, 'applications/'), ['electrum.desktop']),
        (os.path.join(usr_share, icons_dirname), ['icons/electrum.png'])
    ]

extras_require = {
    'hardware': requirements_hw,
    'fast': ['pycryptodomex'],
}
extras_require['full'] = extras_require['hardware'] + extras_require['fast']


setup(
    name="Ocean Wallet",
    version=version.ELECTRUM_VERSION,
    install_requires=requirements,
    extras_require=extras_require,
    packages=[
        'electrum',
        'electrum.gui',
        'electrum.gui.qt',
        'electrum.btchip_ocean',
        'electrum.plugins'
    ] + [('electrum.plugins.'+pkg) for pkg in find_packages('electrum/plugins')],
    package_dir={
        'electrum': 'electrum'
    },
    package_data={
        '': ['*.txt', '*.json', '*.ttf', '*.otf'],
        'electrum': [
            'wordlist/*.txt',
            'locale/*/LC_MESSAGES/electrum.mo',
            'contract/contract'
        ],
    },
    scripts=['electrum/electrum'],
    data_files=data_files,
    description="Lightweight Ocean Wallet",
    author="Thomas Voegtlin,CommerceBlockDevs",
    author_email="nikolaos@commerceblock.com",
    license="MIT Licence",
    url="https://commerceblock.com",
    long_description="""Lightweight Ocean Wallet"""
)
