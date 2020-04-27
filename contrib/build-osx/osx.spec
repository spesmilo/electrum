# -*- mode: python -*-

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, collect_dynamic_libs

import sys
import os

PACKAGE='Ocean Wallet'
PYPKG='electrum'
MAIN_SCRIPT='run_electrum'
ICONS_FILE='ocean.icns'

for i, x in enumerate(sys.argv):
    if x == '--name':
        VERSION = sys.argv[i+1]
        break
else:
    raise Exception('no version')

electrum = os.path.abspath(".") + "/"
block_cipher = None

# see https://github.com/pyinstaller/pyinstaller/issues/2005
hiddenimports = []
hiddenimports += collect_submodules('pkg_resources')  # workaround for https://github.com/pypa/setuptools/issues/1963
hiddenimports += collect_submodules('trezorlib')
hiddenimports += collect_submodules('safetlib')
hiddenimports += collect_submodules('btchip')
hiddenimports += collect_submodules('bitcoin')
hiddenimports += collect_submodules('keepkeylib')
hiddenimports += collect_submodules('websocket')

datas = [
    (electrum+'electrum/*.json', PYPKG),
    (electrum+'electrum/wordlist/english.txt', PYPKG + '/wordlist'),
    (electrum+'electrum/locale', PYPKG + '/locale'),
    (electrum+'electrum/plugins', PYPKG + '/plugins'),
    (electrum+'electrum/contract/contract', PYPKG + '/contract')
]
datas += collect_data_files('trezorlib')
datas += collect_data_files('safetlib')
datas += collect_data_files('btchip')
datas += collect_data_files('bitcoin')
datas += collect_data_files('keepkeylib')

# Add libusb so Trezor and Safe-T mini will work
binaries = [(electrum + "contrib/build-osx/libusb-1.0.dylib", ".")]
binaries += [(electrum + "contrib/build-osx/libsecp256k1.0.dylib", ".")]

# Workaround for "Retro Look":
binaries += [b for b in collect_dynamic_libs('PyQt5') if 'macstyle' in b[0]]

# We don't put these files in to actually include them in the script but to make the Analysis method scan them for imports
a = Analysis([electrum+ MAIN_SCRIPT,
              electrum+'electrum/gui/qt/main_window.py',
              electrum+'electrum/gui/text.py',
              electrum+'electrum/util.py',
              electrum+'electrum/wallet.py',
              electrum+'electrum/simple_config.py',
              electrum+'electrum/bitcoin.py',
              electrum+'electrum/dnssec.py',
              electrum+'electrum/commands.py',
              electrum+'electrum/plugins/cosigner_pool/qt.py',
              electrum+'electrum/plugins/email_requests/qt.py',
              electrum+'electrum/plugins/trezor/client.py',
              electrum+'electrum/plugins/trezor/qt.py',
              electrum+'electrum/plugins/safe_t/client.py',
              electrum+'electrum/plugins/safe_t/qt.py',
              electrum+'electrum/plugins/keepkey/qt.py',
              electrum+'electrum/plugins/ledger/qt.py',
              electrum+'electrum/plugins/ledger/btchip.py',
              electrum+'electrum/plugins/ledger/oceanTransaction.py',
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

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.datas,
          name=PACKAGE,
          debug=False,
          strip=False,
          upx=True,
          icon=electrum+ICONS_FILE,
          console=False)

app = BUNDLE(exe,
             version = VERSION,
             name=PACKAGE + '.app',
             icon=electrum+ICONS_FILE,
             bundle_identifier=None,
             info_plist={
                'NSHighResolutionCapable': 'True',
                'NSSupportsAutomaticGraphicsSwitching': 'True'
             }
)
