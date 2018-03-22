#!/usr/bin/env python3

# python setup.py sdist --format=zip,gztar

import os
import sys
import platform
import importlib.util
import argparse
import subprocess

from distutils import core
from setuptools import setup, find_packages
from setuptools.command.build_py import build_py
from setuptools.command.install import install

MIN_PYTHON_VERSION = "3.6.1"
_min_python_version_tuple = tuple(map(int, (MIN_PYTHON_VERSION.split("."))))


if sys.version_info[:3] < _min_python_version_tuple:
    sys.exit("Error: Electrum requires Python version >= %s..." % MIN_PYTHON_VERSION)

with open('contrib/requirements/requirements.txt') as f:
    requirements = f.read().splitlines()

with open('contrib/requirements/requirements-hw.txt') as f:
    requirements_hw = f.read().splitlines()

# load version.py; needlessly complicated alternative to "imp.load_source":
version_spec = importlib.util.spec_from_file_location('version', 'electrum/version.py')
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
        (os.path.join(usr_share, 'applications/'), ['electrum-ftc.desktop']),
        (os.path.join(usr_share, icons_dirname), ['electrum/gui/icons/electrum.png']),
    ]

extras_require = {
    'hardware': requirements_hw,
    'fast': ['pycryptodomex'],
    'gui': ['pyqt5'],
}
extras_require['full'] = [pkg for sublist in list(extras_require.values()) for pkg in sublist]


class CustomInstallCommand(install):
    def run(self):
        setup = core.run_setup('neoscrypt_module/setup.py', stop_after='commandline')
        setup.run_command('install')
        install.run(self)

class BuildPyCommand(build_py):
    def run(self):
        build_py.run(self)
        with open('build/lib/electrum_ftc/version.py', 'r+') as fp:
            verfile = fp.readlines()
            verfile[0] = "ELECTRUM_FTC_VERSION = '{}'\n".format(
                version.ELECTRUM_FTC_VERSION)
            fp.seek(0)
            fp.writelines(verfile)
            fp.truncate()

setup(
    name="Electrum-FTC",
    version=version.ELECTRUM_FTC_VERSION,
    python_requires='>={}'.format(MIN_PYTHON_VERSION),
    install_requires=requirements,
    extras_require=extras_require,
    packages=[
        pkg.replace("electrum", "electrum_ftc") for pkg in find_packages(
            exclude=['*.tests', '*.kivy', '*.kivy.*'])
    ],
    package_dir={
        'electrum_ftc': 'electrum'
    },
    package_data={
        '': ['*.txt', '*.json', '*.ttf', '*.otf'],
        'electrum_ftc': [
            'wordlist/*.txt',
            'locale/*/LC_MESSAGES/electrum.mo',
        ],
        'electrum.gui': [
            'icons/*',
        ],
    },
    scripts=['electrum/electrum'],
    data_files=data_files,
    description="Lightweight Feathercoin Wallet",
    author="Thomas Voegtlin; Feathercoin Development Foundation",
    author_email="thomasv@electrum.org; info@feathercoin.foundation",
    license="MIT Licence",
    url="https://electrum.org",
    long_description="""Lightweight Feathercoin Wallet""",
    cmdclass={
        'build_py': BuildPyCommand,
        'install': CustomInstallCommand,
    },
)
