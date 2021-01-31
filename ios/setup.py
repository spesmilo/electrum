#!/usr/bin/env python3
import io
import re
from setuptools import setup, find_packages
import sys

with io.open('./common.sh') as f:
    contents = f.read()
    name_match = re.search(r"^ *compact_name *= *['\"]([^'\"]*)['\"]", contents, re.M)
    if name_match:
        compact_name=name_match.group(1)
    else:
        raise RuntimeError("Unable to find compact_name in ./common.sh")

    formal_name_match = re.search(r"^ *xcode_target *= *['\"]([^'\"]*)['\"]", contents, re.M)
    if formal_name_match:
        formal_name=formal_name_match.group(1)
    else:
        raise RuntimeError("Unable to find xcode_target in ./common.sh")
    del name_match, formal_name_match, contents

version_py = './{}/electroncash/version.py'.format(compact_name)
with io.open(version_py, encoding='utf8') as version_file:
    version_match = re.search(r"^ *PACKAGE_VERSION *= *['\"]([^'\"]*)['\"]", version_file.read(), re.M)
    if version_match:
        version = version_match.group(1)
    else:
        raise RuntimeError("Unable to find PACKAGE_VERSION in {}.".format(version_py))
    del version_match, version_py


with io.open('README.rst', encoding='utf8') as readme:
    long_description = readme.read()


setup(
    name=compact_name, # comes from common.sh
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
        'pyaes>=0.1a1',
        'PySocks>=1.6.6', 'qrcode', 'requests', 'six', 'stem==1.8.0',
        'urllib3<1.24', 'python-dateutil==2.6.1', 'pathvalidate==2.3.1'
    ],
    options={
        'app': {
            'formal_name': formal_name, # comes from common.sh
            'bundle': 'com.c3-soft'
        },

        # Mobile deployments
        'ios': {
            'app_requires': [
                'rubicon-objc==0.2.10'
            ]
        },
    }
)
