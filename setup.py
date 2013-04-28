#!/usr/bin/python

# python setup.py sdist --format=zip,gztar

from distutils.core import setup
import os, sys, platform, imp

version = imp.load_source('version', 'lib/version.py')
util = imp.load_source('version', 'lib/util.py')

if sys.version_info[:3] < (2,6,0):
    sys.exit("Error: Electrum requires Python version >= 2.6.0...")

data_files = []
if (len(sys.argv) > 1 and (sys.argv[1] == "sdist")) or (platform.system() != 'Windows' and platform.system() != 'Darwin'):
    print "Including all files"
    data_files += [
        ('/usr/share/applications/',['electrum.desktop']),
        ('/usr/share/app-install/icons/',['icons/electrum.png'])
    ]
    if not os.path.exists('locale'):
        os.mkdir('locale')
    for lang in os.listdir('locale'):
        if os.path.exists('locale/%s/LC_MESSAGES/electrum.mo'%lang):
            data_files.append(  ('/usr/share/locale/%s/LC_MESSAGES'%lang, ['locale/%s/LC_MESSAGES/electrum.mo'%lang]) )

data_files += [
    (util.appdata_dir(), ["data/README"]),
    (os.path.join(util.appdata_dir(), "cleanlook"), [
        "data/cleanlook/name.cfg",
        "data/cleanlook/style.css"
    ]),
    (os.path.join(util.appdata_dir(), "sahara"), [
        "data/sahara/name.cfg",
        "data/sahara/style.css"
    ]),    
    (os.path.join(util.appdata_dir(), "dark"), [
        "data/dark/background.png",
        "data/dark/name.cfg",
        "data/dark/style.css"
    ])
]


setup(name = "Electrum",
    version = version.ELECTRUM_VERSION,
    install_requires = ['slowaes','ecdsa'],
    package_dir = {'electrum': 'lib', 'electrum_gui': 'gui', 'electrum_plugins':'plugins'},
    scripts= ['electrum'],
    data_files = data_files,
    py_modules = ['electrum.version',
                  'electrum.wallet',
                  'electrum.wallet_bitkey',
                  'electrum.wallet_factory',
                  'electrum.interface',
                  'electrum.commands',
                  'electrum.mnemonic',
                  'electrum.simple_config',
                  'electrum.socks',
                  'electrum.msqr',
                  'electrum.util',
                  'electrum.bitcoin',
                  'electrum.deserialize',
                  'electrum.verifier',
                  'electrum_gui.gui_gtk',
                  'electrum_gui.qt_console',
                  'electrum_gui.gui_classic',
                  'electrum_gui.gui_lite',
                  'electrum_gui.gui_text',
                  'electrum_gui.exchange_rate',
                  'electrum_gui.icons_rc',
                  'electrum_gui.pyqrnative',
                  'electrum_gui.qrcodewidget',
                  'electrum_gui.history_widget',
                  'electrum_gui.receiving_widget',
                  'electrum_gui.qt_util',
                  'electrum_gui.network_dialog',
                  'electrum_gui.bmp',
                  'electrum_gui.i18n',
                  'electrum_gui.plugins',
                  'electrum_gui.amountedit',
                  'electrum_plugins.pointofsale',
                  'electrum_plugins.qrscanner',
                  'electrum_plugins.aliases',
                  'electrum_plugins.labels',
                  'electrum_plugins.virtualkeyboard',
                  ],
    description = "Lightweight Bitcoin Wallet",
    author = "ecdsa",
    author_email = "ecdsa@github",
    license = "GNU GPLv3",
    url = "http://electrum-desktop.com",
    long_description = """Lightweight Bitcoin Wallet""" 
)


