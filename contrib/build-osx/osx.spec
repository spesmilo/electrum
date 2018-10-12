# -*- mode: python -*-

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, collect_dynamic_libs

import sys
import os

PACKAGE='Electrum-GRS'
PYPKG='electrum_grs'
MAIN_SCRIPT='run_electrum_grs'
ICONS_FILE='electrum-grs.icns'

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
hiddenimports += collect_submodules('trezorlib')
hiddenimports += collect_submodules('safetlib')
hiddenimports += collect_submodules('btchip')
hiddenimports += collect_submodules('keepkeylib')
hiddenimports += collect_submodules('websocket')
hiddenimports += collect_submodules('ckcc')

datas = [
    (electrum + PYPKG + '/*.json', PYPKG),
    (electrum + PYPKG + '/wordlist/english.txt', PYPKG + '/wordlist'),
    (electrum + PYPKG + '/locale', PYPKG + '/locale'),
    (electrum + PYPKG + '/plugins', PYPKG + '/plugins'),
]
datas += collect_data_files('trezorlib')
datas += collect_data_files('safetlib')
datas += collect_data_files('btchip')
datas += collect_data_files('keepkeylib')
datas += collect_data_files('ckcc')

# Add libusb so Trezor and Safe-T mini will work
binaries = [(electrum + "contrib/build-osx/libusb-1.0.dylib", ".")]
binaries += [(electrum + "contrib/build-osx/libsecp256k1.0.dylib", ".")]

# Workaround for "Retro Look":
binaries += [b for b in collect_dynamic_libs('PyQt5') if 'macstyle' in b[0]]

# We don't put these files in to actually include them in the script but to make the Analysis method scan them for imports
a = Analysis([electrum+ MAIN_SCRIPT,
              electrum+'electrum_grs/gui/qt/main_window.py',
              electrum+'electrum_grs/gui/text.py',
              electrum+'electrum_grs/util.py',
              electrum+'electrum_grs/wallet.py',
              electrum+'electrum_grs/simple_config.py',
              electrum+'electrum_grs/bitcoin.py',
              electrum+'electrum_grs/dnssec.py',
              electrum+'electrum_grs/commands.py',
              electrum+'electrum_grs/plugins/cosigner_pool/qt.py',
              electrum+'electrum_grs/plugins/email_requests/qt.py',
              electrum+'electrum_grs/plugins/trezor/client.py',
              electrum+'electrum_grs/plugins/trezor/qt.py',
              electrum+'electrum_grs/plugins/safe_t/client.py',
              electrum+'electrum_grs/plugins/safe_t/qt.py',
              electrum+'electrum_grs/plugins/keepkey/qt.py',
              electrum+'electrum_grs/plugins/ledger/qt.py',
              electrum+'electrum_grs/plugins/coldcard/qt.py',
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
