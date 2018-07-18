#!/usr/bin/env python
import io
import re
from setuptools import setup, find_packages
import sys

with io.open('./ElectronCash/__init__.py', encoding='utf8') as version_file:
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", version_file.read(), re.M)
    if version_match:
        version = version_match.group(1)
    else:
        raise RuntimeError("Unable to find version string.")


with io.open('README.rst', encoding='utf8') as readme:
    long_description = readme.read()


setup(
    name='ElectronCash',
    version=version,
    description='A Bitcoin Cash SPV Wallet',
    long_description=long_description,
    author='Calin Culianu',
    author_email='calin.culianu@gmail.com',
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
        'jsonrpclib-pelix', 'protobuf',
        'pyaes>=0.1a1', #'pyOpenSSL>=17.5.0', 
        'PySocks>=1.6.6', 'qrcode', 'requests', 'six',
        'urllib3' #, 'pyqt5'
    ],
    options={
        'app': {
            'formal_name': 'Electron-Cash',
            'bundle': 'com.c3-soft'
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
