# -*- mode: python3 -*-

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, collect_dynamic_libs
import sys, os

PACKAGE='Electron-Cash'
BUNDLE_IDENTIFIER='org.electroncash.' + PACKAGE # Used for info.plist
PYPKG='electroncash'
MAIN_SCRIPT='electron-cash'
ICONS_FILE='electron.icns'

for i, x in enumerate(sys.argv):
    if x == '--name':
        VERSION = sys.argv[i+1]
        break
else:
    raise BaseException('no version')

home = os.path.abspath(".") + "/"
block_cipher = None

# see https://github.com/pyinstaller/pyinstaller/issues/2005
hiddenimports = []
hiddenimports += collect_submodules('trezorlib')
hiddenimports += collect_submodules('btchip')
hiddenimports += collect_submodules('keepkeylib')
hiddenimports += collect_submodules('satochip')    # Satochip
hiddenimports += collect_submodules('smartcard')   # Satochip

datas = [
    (home+'electroncash/currencies.json', PYPKG),
    (home+'electroncash/servers.json', PYPKG),
    (home+'electroncash/servers_testnet.json', PYPKG),
    (home+'electroncash/servers_testnet4.json', PYPKG),
    (home+'electroncash/servers_scalenet.json', PYPKG),
    (home+'electroncash/servers_taxcoin.json', PYPKG),
    (home+'electroncash/wordlist/english.txt', PYPKG + '/wordlist'),
    (home+'electroncash_gui/qt/data/ard_mone.mp3', PYPKG + '_gui' + '/data'),
    (home+'electroncash/locale', PYPKG + '/locale'),
    (home+'electroncash_plugins', PYPKG + '_plugins'),
]
datas += collect_data_files('trezorlib')
datas += collect_data_files('btchip')
datas += collect_data_files('keepkeylib')
datas += collect_data_files('mnemonic')  # wordlists used by keepkeylib from lib mnemonic


# Add libusb so Trezor will work
binaries = [(home + "contrib/osx/libusb-1.0.dylib", ".")]
# LibSecp for fast ECDSA and Schnorr
binaries += [(home + "contrib/osx/libsecp256k1.0.dylib", ".")]
# LibZBar for QR code scanning
binaries += [(home + "contrib/osx/libzbar.0.dylib", ".")]
# Add Tor binary
binaries += [(home + "electroncash/tor/bin/tor", "electroncash/tor/bin")]

# Workaround for "Retro Look":
binaries += [b for b in collect_dynamic_libs('PyQt5') if 'macstyle' in b[0]]

# We don't put these files in to actually include them in the script but to make the Analysis method scan them for imports
a = Analysis([home+MAIN_SCRIPT,
              home+'electroncash_gui/qt/main_window.py',
              home+'electroncash_gui/qt/qrreader/camera_dialog.py',
              home+'electroncash_gui/text.py',
              home+'electroncash/util.py',
              home+'electroncash/wallet.py',
              home+'electroncash/simple_config.py',
              home+'electroncash/bitcoin.py',
              home+'electroncash/dnssec.py',
              home+'electroncash/commands.py',
              home+'electroncash/tor/controller.py',
              home+'electroncash_plugins/cosigner_pool/qt.py',
              home+'electroncash_plugins/email_requests/qt.py',
              home+'electroncash_plugins/trezor/clientbase.py',
              home+'electroncash_plugins/trezor/trezor.py',
              home+'electroncash_plugins/trezor/qt.py',
              home+'electroncash_plugins/keepkey/qt.py',
              home+'electroncash_plugins/ledger/qt.py',
              home+'electroncash_plugins/satochip/qt.py',  # Satochip
              home+'electroncash_plugins/fusion/fusion.py', # CashFusion
              home+'electroncash_plugins/fusion/qt.py', # CashFusion
              ],
             binaries=binaries,
             datas=datas,
             hiddenimports=hiddenimports,
             hookspath=[])

# http://stackoverflow.com/questions/19055089/pyinstaller-onefile-warning-pyconfig-h-when-importing-scipy-or-scipy-signal
for d in a.datas:
    if 'pyconfig' in d[0]:
        a.datas.remove(d)
        break
# Remove QtWeb and other stuff that we know we never use.
# This is a hack of sorts that works to keep the binary file size reasonable.
bins2remove=('qtweb', 'qt3d', 'qtgame', 'qtdesigner', 'qtquick', 'qtlocation',
             'qttest', 'qtxml', 'qtqml', 'qtsql', 'qtserialport', 'qtsensors',
             'qtpositioning', 'qtnfc', 'qthelp', 'qtbluetooth',
             'pyqt5/qt/qml', 'pyqt5/qt/plugins/position',
             'pyqt5/qt/plugins/sqldrivers', )
files2remove=('libqsqlmysql.dylib', 'libdeclarative_multimedia.dylib',
              'libqtquickscene2dplugin.dylib', 'libqtquickscene3dplugin.dylib',
              'libqtquickcontrols2imaginestyleplugin.dylib', 'libqwebgl.dylib',
              'libqtquickextrasflatplugin.dylib', 'ibqtcanvas3d.dylib',
              'libqtquickcontrolsplugin.dylib', 'libqtquicktemplates2plugin.dylib',
              'libqtlabsplatformplugin.dylib', 'libdeclarative_sensors.dylib',
              'libdeclarative_location.dylib', )
print("Removing", *(bins2remove + files2remove))
for x in a.binaries.copy():
    item = x[0].lower()
    fn = x[1].lower()
    if os.path.basename(fn) in files2remove:
        a.binaries.remove(x)
        print('----> Removed:', x)
        continue
    for r in bins2remove:
        pyqt5_r = 'pyqt5.' + r
        if item.startswith(r) or item.startswith(pyqt5_r):
            a.binaries.remove(x)
            print('----> Removed:', x)
            break # break from inner loop
#

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name=PACKAGE,
    debug=False,
    strip=False,
    upx=False,
    icon=home+ICONS_FILE,
    console=False
)

app = BUNDLE(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    version = VERSION,
    name=PACKAGE + '.app',
    icon=home+ICONS_FILE,
    bundle_identifier=BUNDLE_IDENTIFIER,
    info_plist = {
        'NSHighResolutionCapable':'True',
        'NSSupportsAutomaticGraphicsSwitching':'True'
    }
)
