#!/usr/bin/env python3

# python setup.py sdist --format=zip,gztar

import os
import sys
import platform
import importlib.util
import argparse
import subprocess

from setuptools import setup, find_packages
from setuptools.command.install import install

MIN_PYTHON_VERSION = "3.6.1"
_min_python_version_tuple = tuple(map(int, (MIN_PYTHON_VERSION.split("."))))


if sys.version_info[:3] < _min_python_version_tuple:
    sys.exit("Error: Electrum-GRS requires Python version >= %s..." % MIN_PYTHON_VERSION)

with open('contrib/requirements/requirements.txt') as f:
    requirements = f.read().splitlines()

with open('contrib/requirements/requirements-hw.txt') as f:
    requirements_hw = f.read().splitlines()

# load version.py; needlessly complicated alternative to "imp.load_source":
version_spec = importlib.util.spec_from_file_location('version', 'electrum_grs/version.py')
version_module = version = importlib.util.module_from_spec(version_spec)
version_spec.loader.exec_module(version_module)

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
        (os.path.join(usr_share, 'applications/'), ['electrum-grs.desktop']),
        (os.path.join(usr_share, icons_dirname), ['electrum_grs/gui/icons/electrum-grs.png']),
    ]

extras_require = {
    'hardware': requirements_hw,
    'gui': ['pyqt5'],
    'crypto': ['pycryptodomex>=3.7'],
    'tests': ['pycryptodomex>=3.7', 'cryptography>=2.1'],
}
# 'full' extra that tries to grab everything an enduser would need (except for libsecp256k1...)
extras_require['full'] = [pkg for sublist in ['hardware', 'gui', 'crypto'] for pkg in sublist]
# legacy. keep 'fast' extra working
extras_require['fast'] = extras_require['crypto']


setup(
    name="Electrum-grs",
    version=version.ELECTRUM_VERSION,
    python_requires='>={}'.format(MIN_PYTHON_VERSION),
    install_requires=requirements,
    extras_require=extras_require,
    packages=[
        'electrum_grs',
        'electrum_grs.gui',
        'electrum_grs.gui.qt',
        'electrum_grs.plugins',
    ] + [('electrum_grs.plugins.'+pkg) for pkg in find_packages('electrum_grs/plugins')],
    package_dir={
        'electrum_grs': 'electrum_grs'
    },
    package_data={
        '': ['*.txt', '*.json', '*.ttf', '*.otf', '*.csv'],
        'electrum_grs': [
            'wordlist/*.txt',
            'locale/*/LC_MESSAGES/electrum.mo',
            'lnwire/*.csv',
        ],
        'electrum_grs.gui': [
            'icons/*',
        ],
    },
    scripts=['electrum_grs/electrum-grs'],
    data_files=data_files,
    description="Lightweight Groestlcoin Wallet",
    author="Groestlcoin Developers",
    author_email="groestlcoin@gmail.com",
    license="MIT Licence",
    url="https://groestlcoin.org",
    long_description="""Lightweight Groestlcoin Wallet""",
)
