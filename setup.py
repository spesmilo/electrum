#!/usr/bin/python

# python setup.py sdist --format=zip,gztar

from setuptools import setup
import os
import sys
import platform
import imp


version = imp.load_source('version', 'lib/version.py')
util = imp.load_source('util', 'lib/util.py')

if sys.version_info[:3] < (2, 7, 0):
    sys.exit("Error: Electrum requires Python version >= 2.7.0...")



if (len(sys.argv) > 1) and (sys.argv[1] == "install"): 
    # or (platform.system() != 'Windows' and platform.system() != 'Darwin'):
    print "Including all files"
    data_files = []
    usr_share = util.usr_share_dir()
    if not os.access(usr_share, os.W_OK):
        try:
            os.mkdir(usr_share)
        except:
            sys.exit("Error: cannot write to %s.\nIf you do not have root permissions, you may install Electrum in a virtualenv.\nAlso, please note that you can run Electrum without installing it on your system."%usr_share)

    data_files += [
        (os.path.join(usr_share, 'applications/'), ['electrum.desktop']),
        (os.path.join(usr_share, 'app-install', 'icons/'), ['icons/electrum.png'])
    ]
    if not os.path.exists('locale'):
        os.mkdir('locale')
    for lang in os.listdir('locale'):
        if os.path.exists('locale/%s/LC_MESSAGES/electrum.mo' % lang):
            data_files.append((os.path.join(usr_share, 'locale/%s/LC_MESSAGES' % lang), ['locale/%s/LC_MESSAGES/electrum.mo' % lang]))


    appdata_dir = os.path.join(usr_share, "electrum")
    data_files += [
        (appdata_dir, ["data/README"]),
        (os.path.join(appdata_dir, "cleanlook"), [
            "data/cleanlook/name.cfg",
            "data/cleanlook/style.css"
        ]),
        (os.path.join(appdata_dir, "sahara"), [
            "data/sahara/name.cfg",
            "data/sahara/style.css"
        ]),
        (os.path.join(appdata_dir, "dark"), [
            "data/dark/name.cfg",
            "data/dark/style.css"
        ])
    ]

    for lang in os.listdir('data/wordlist'):
        data_files.append((os.path.join(appdata_dir, 'wordlist'), ['data/wordlist/%s' % lang]))
else:
    data_files = []

setup(
    name="Electrum",
    version=version.ELECTRUM_VERSION,
    install_requires=[
        'slowaes>=0.1a1',
        'ecdsa>=0.9',
        'pbkdf2',
        'requests',
        'pyasn1-modules',
        'pyasn1',
        'qrcode',
        'SocksiPy-branch',
        'protobuf',
        'tlslite'
    ],
    package_dir={
        'electrum': 'lib',
        'electrum_gui': 'gui',
        'electrum_plugins': 'plugins',
    },
    scripts=['electrum'],
    data_files=data_files,
    py_modules=[
        'electrum.account',
        'electrum.bitcoin',
        'electrum.blockchain',
        'electrum.bmp',
        'electrum.commands',
        'electrum.daemon',
        'electrum.i18n',
        'electrum.interface',
        'electrum.mnemonic',
        'electrum.msqr',
        'electrum.network',
        'electrum.network_proxy',
        'electrum.old_mnemonic',
        'electrum.paymentrequest',
        'electrum.paymentrequest_pb2',
        'electrum.plugins',
        'electrum.qrscanner',
        'electrum.simple_config',
        'electrum.synchronizer',
        'electrum.transaction',
        'electrum.util',
        'electrum.verifier',
        'electrum.version',
        'electrum.wallet',
        'electrum.x509',
        'electrum_gui.gtk',
        'electrum_gui.qt.__init__',
        'electrum_gui.qt.amountedit',
        'electrum_gui.qt.console',
        'electrum_gui.qt.history_widget',
        'electrum_gui.qt.icons_rc',
        'electrum_gui.qt.installwizard',
        'electrum_gui.qt.lite_window',
        'electrum_gui.qt.main_window',
        'electrum_gui.qt.network_dialog',
        'electrum_gui.qt.password_dialog',
        'electrum_gui.qt.paytoedit',
        'electrum_gui.qt.qrcodewidget',
        'electrum_gui.qt.qrtextedit',
        'electrum_gui.qt.qrwindow',
        'electrum_gui.qt.receiving_widget',
        'electrum_gui.qt.seed_dialog',
        'electrum_gui.qt.transaction_dialog',
        'electrum_gui.qt.util',
        'electrum_gui.qt.version_getter',
        'electrum_gui.stdio',
        'electrum_gui.text',
        'electrum_plugins.btchipwallet',
        'electrum_plugins.coinbase_buyback',
        'electrum_plugins.cosigner_pool',
        'electrum_plugins.exchange_rate',
        'electrum_plugins.greenaddress_instant',
        'electrum_plugins.labels',
        'electrum_plugins.trezor',
        'electrum_plugins.virtualkeyboard',
        'electrum_plugins.plot',

    ],
    description="Lightweight Bitcoin Wallet",
    author="Thomas Voegtlin",
    author_email="thomasv1@gmx.de",
    license="GNU GPLv3",
    url="https://electrum.org",
    long_description="""Lightweight Bitcoin Wallet"""
)
