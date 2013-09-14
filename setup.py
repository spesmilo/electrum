#!/usr/bin/python

# python setup.py sdist --format=zip,gztar

from distutils.core import setup
import os, sys, platform, imp

version = imp.load_source('version', 'lib/version.py')
util = imp.load_source('version', 'lib/util.py')

if sys.version_info[:3] < (2,6,0):
    sys.exit("Error: Electrum requires Python version >= 2.6.0...")

usr_share = '/usr/share'
if not os.access(usr_share, os.W_OK):
    usr_share = os.getenv("XDG_DATA_HOME",
                           os.path.join(os.getenv("HOME"), ".local", "share"))

data_files = []
if (len(sys.argv) > 1 and (sys.argv[1] == "sdist")) or (platform.system() != 'Windows' and platform.system() != 'Darwin'):
    print "Including all files"
    data_files += [
        (os.path.join(usr_share, 'applications/'),['electrum.desktop']),
        (os.path.join(usr_share, 'app-install', 'icons/'),['icons/electrum.png'])
    ]
    if not os.path.exists('locale'):
        os.mkdir('locale')
    for lang in os.listdir('locale'):
        if os.path.exists('locale/%s/LC_MESSAGES/electrum.mo'%lang):
            data_files.append(  (os.path.join(usr_share, 'locale/%s/LC_MESSAGES'%lang), ['locale/%s/LC_MESSAGES/electrum.mo'%lang]) )

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
    py_modules = ['electrum.account',
                  'electrum.bitcoin',
                  'electrum.blockchain',
                  'electrum.commands',
                  'electrum.interface',
                  'electrum.mnemonic',
                  'electrum.msqr',
                  'electrum.network',
                  'electrum.simple_config',
                  'electrum.socks',
                  'electrum.transaction',
                  'electrum.util',
                  'electrum.version',
                  'electrum.verifier',
                  'electrum.wallet',
                  'electrum.wallet_bitkey',
                  'electrum.wallet_factory',
                  'electrum.bmp',
                  'electrum.i18n',
                  'electrum.pyqrnative',
                  'electrum.plugins',
                  'electrum_gui.gui_gtk',
                  'electrum_gui.gui_text',
                  'electrum_gui.gui_classic',
                  'electrum_gui.gui_classic.qt_console',
                  'electrum_gui.gui_classic.lite_window',
                  'electrum_gui.gui_classic.main_window',
                  'electrum_gui.gui_classic.installwizard',
                  'electrum_gui.gui_classic.exchange_rate',
                  'electrum_gui.gui_classic.icons_rc',
                  'electrum_gui.gui_classic.qrcodewidget',
                  'electrum_gui.gui_classic.history_widget',
                  'electrum_gui.gui_classic.receiving_widget',
                  'electrum_gui.gui_classic.qt_util',
                  'electrum_gui.gui_classic.network_dialog',
                  'electrum_gui.gui_classic.password_dialog',
                  'electrum_gui.gui_classic.seed_dialog',
                  'electrum_gui.gui_classic.transaction dialog',
                  'electrum_gui.gui_classic.version_getter',
                  'electrum_gui.gui_classic.amountedit',
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


