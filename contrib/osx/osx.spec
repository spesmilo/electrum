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
    (home+'lib/currencies.json', PYPKG),
    (home+'lib/servers.json', PYPKG),
    (home+'lib/servers_testnet.json', PYPKG),
    (home+'lib/wordlist/english.txt', PYPKG + '/wordlist'),
    (home+'lib/locale', PYPKG + '/locale'),
    (home+'plugins', PYPKG + '_plugins'),
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
binaries += [(home + "lib/tor/bin/tor", ".")]

# Workaround for "Retro Look":
binaries += [b for b in collect_dynamic_libs('PyQt5') if 'macstyle' in b[0]]

# We don't put these files in to actually include them in the script but to make the Analysis method scan them for imports
a = Analysis([home+MAIN_SCRIPT,
              home+'gui/qt/main_window.py',
              home+'gui/qt/qrreader/camera_dialog.py',
              home+'gui/text.py',
              home+'lib/util.py',
              home+'lib/wallet.py',
              home+'lib/simple_config.py',
              home+'lib/bitcoin.py',
              home+'lib/dnssec.py',
              home+'lib/commands.py',
              home+'lib/tor/controller.py',
              home+'plugins/cosigner_pool/qt.py',
              home+'plugins/email_requests/qt.py',
              home+'plugins/trezor/clientbase.py',
              home+'plugins/trezor/trezor.py',
              home+'plugins/trezor/qt.py',
              home+'plugins/keepkey/qt.py',
              home+'plugins/ledger/qt.py',
              home+'plugins/satochip/qt.py',  # Satochip
              home+'plugins/fusion/fusion.py', # CashFusion
              home+'plugins/fusion/qt.py', # CashFusion
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
             'pyqt5/qt/plugins/audio',
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

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.datas,
          name=PACKAGE,
          debug=False,
          strip=False,
          upx=False,
          icon=home+ICONS_FILE,
          console=False)

app = BUNDLE(exe,
             version = VERSION,
             name=PACKAGE + '.app',
             icon=home+ICONS_FILE,
             bundle_identifier=BUNDLE_IDENTIFIER,
             info_plist = {
                 'NSHighResolutionCapable':'True',
                 'NSSupportsAutomaticGraphicsSwitching':'True'
             }
)
