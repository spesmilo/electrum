#!/usr/bin/python

# python setup.py sdist --format=zip,gztar

from setuptools import setup
import os
import sys
import platform
import imp


version = imp.load_source('version', 'lib/version.py')
util = imp.load_source('version', 'lib/util.py')

if sys.version_info[:3] < (2, 6, 0):
    sys.exit("Error: Electrum requires Python version >= 2.6.0...")

usr_share = '/usr/share'
if not os.access(usr_share, os.W_OK):
    usr_share = os.getenv("XDG_DATA_HOME", os.path.join(os.getenv("HOME"), ".local", "share"))

data_files = []
if (len(sys.argv) > 1 and (sys.argv[1] == "sdist")) or (platform.system() != 'Windows' and platform.system() != 'Darwin'):
    print "Including all files"
    data_files += [
        (os.path.join(usr_share, 'applications/'), ['electrum-ltc.desktop']),
        (os.path.join(usr_share, 'app-install', 'icons/'), ['icons/electrum-ltc.png'])
    ]
    if not os.path.exists('locale'):
        os.mkdir('locale')
    for lang in os.listdir('locale'):
        if os.path.exists('locale/%s/LC_MESSAGES/electrum.mo' % lang):
            data_files.append((os.path.join(usr_share, 'locale/%s/LC_MESSAGES' % lang), ['locale/%s/LC_MESSAGES/electrum.mo' % lang]))

appdata_dir = util.appdata_dir()
if not os.access(appdata_dir, os.W_OK):
    appdata_dir = os.path.join(usr_share, "electrum-ltc")

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


setup(
    name="Electrum-LTC",
    version=version.ELECTRUM_VERSION,
    install_requires=['slowaes', 'ecdsa>=0.9', 'ltc_scrypt'],
    package_dir={
        'electrum_ltc': 'lib',
        'electrum_ltc_gui': 'gui',
        'electrum_ltc_plugins': 'plugins',
    },
    scripts=['electrum-ltc'],
    data_files=data_files,
    py_modules=[
        'electrum_ltc.account',
        'electrum_ltc.bitcoin',
        'electrum_ltc.blockchain',
        'electrum_ltc.bmp',
        'electrum_ltc.commands',
        'electrum_ltc.daemon',
        'electrum_ltc.i18n',
        'electrum_ltc.interface',
        'electrum_ltc.mnemonic',
        'electrum_ltc.msqr',
        'electrum_ltc.network',
        'electrum_ltc.plugins',
        'electrum_ltc.pyqrnative',
        'electrum_ltc.scrypt',
        'electrum_ltc.simple_config',
        'electrum_ltc.socks',
        'electrum_ltc.transaction',
        'electrum_ltc.util',
        'electrum_ltc.verifier',
        'electrum_ltc.version',
        'electrum_ltc.wallet',
        'electrum_ltc.wallet_bitkey',
        'electrum_ltc_gui.gtk',
        'electrum_ltc_gui.qt.__init__',
        'electrum_ltc_gui.qt.amountedit',
        'electrum_ltc_gui.qt.console',
        'electrum_ltc_gui.qt.history_widget',
        'electrum_ltc_gui.qt.icons_rc',
        'electrum_ltc_gui.qt.installwizard',
        'electrum_ltc_gui.qt.lite_window',
        'electrum_ltc_gui.qt.main_window',
        'electrum_ltc_gui.qt.network_dialog',
        'electrum_ltc_gui.qt.password_dialog',
        'electrum_ltc_gui.qt.qrcodewidget',
        'electrum_ltc_gui.qt.receiving_widget',
        'electrum_ltc_gui.qt.seed_dialog',
        'electrum_ltc_gui.qt.transaction_dialog',
        'electrum_ltc_gui.qt.util',
        'electrum_ltc_gui.qt.version_getter',
        'electrum_ltc_gui.stdio',
        'electrum_ltc_gui.text',
        'electrum_ltc_plugins.aliases',
        'electrum_ltc_plugins.exchange_rate',
        'electrum_ltc_plugins.labels',
        'electrum_ltc_plugins.pointofsale',
        'electrum_ltc_plugins.qrscanner',
        'electrum_ltc_plugins.virtualkeyboard',
    ],
    description="Lightweight Litecoin Wallet",
    author="ecdsa",
    author_email="ecdsa@github",
    license="GNU GPLv3",
    url="http://electrum.org",
    long_description="""Lightweight Litecoin Wallet"""
)
