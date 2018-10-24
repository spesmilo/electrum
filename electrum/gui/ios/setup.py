#!/usr/bin/env python
import io
import re
from setuptools import setup, find_packages
import sys

with io.open('./Electrum/__init__.py', encoding='utf8') as version_file:
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", version_file.read(), re.M)
    if version_match:
        version = version_match.group(1)
    else:
        raise RuntimeError("Unable to find version string.")


with io.open('README.rst', encoding='utf8') as readme:
    long_description = readme.read()


setup(
    name='Electrum',
    version=version,
    description='A Bitcoin SPV Wallet',
    long_description=long_description,
    author='Electrum Technologies GmbH',
    author_email='bauerj@bauerj.eu',
    license='MIT license',
    package_data={'': ["*.json", "*.po", "*.mo", "*.pot", "*.txt", "locale/*", "locale/*/*", "locale/*/*/*", "wordlist/*.txt", "*.png"]},
    include_package_data=True,
    packages=find_packages(
        exclude=[
            'docs', 'tests',
            'windows', 'macOS', 'linux',
            'iOS', 'android',
            'django'
        ]
    ),
    classifiers=[
        'Development Status :: 1 - Planning',
        'License :: OSI Approved :: MIT license',
    ],
    install_requires=[
        'certifi', 'chardet', 'dnspython', 'ecdsa>=0.9', 'idna',
        'jsonrpclib-pelix', 'pbkdf2', 'protobuf', 'aiorpcx>=0.8.2,<0.9',
        'pyaes>=0.1a1', #'pyOpenSSL>=17.5.0', 'aiorpcx>=0.8.2,<0.9',
        'PySocks>=1.6.6', 'qrcode', 'aiohttp', 'aiohttp_socks', 'requests', 'six',
        'urllib3' #, 'pyqt5'
    ],
    options={
        'app': {
            'formal_name': 'Electrum',
            'bundle': 'org.electrum'
        },

        # Mobile deployments
        'ios': {
            'app_requires': [
                'rubicon-objc'
#                'toga-ios'
            ]
        },
    }
)
