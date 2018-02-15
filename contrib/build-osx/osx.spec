# -*- mode: python -*-

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, collect_dynamic_libs

import sys
import os

PACKAGE='Electron-Cash'
PYPKG='electroncash'
MAIN_SCRIPT='electron-cash'
ICONS_FILE='electron.icns'

for i, x in enumerate(sys.argv):
    if x == '--name':
        VERSION = sys.argv[i+1]
        break
else:
    raise BaseException('no version')

electrum = os.path.abspath(".") + "/"
block_cipher = None

# see https://github.com/pyinstaller/pyinstaller/issues/2005
hiddenimports = []
hiddenimports += collect_submodules('trezorlib')
hiddenimports += collect_submodules('btchip')
hiddenimports += collect_submodules('keepkeylib')

datas = [
    (electrum+'lib/currencies.json', PYPKG),
    (electrum+'lib/servers.json', PYPKG),
    (electrum+'lib/wordlist/english.txt', PYPKG + '/wordlist'),
    (electrum+'lib/locale', PYPKG + '/locale'),
    (electrum+'plugins', PYPKG + '_plugins'),
]
datas += collect_data_files('trezorlib')
datas += collect_data_files('btchip')
datas += collect_data_files('keepkeylib')

# We had an issue with PyQt 5.10 not picking up the libqmacstyles.dylib properly,
# and thus Electron Cash looking terrible on Mac.
# The below 3 statements are a workaround for that issue.
# This should 'do nothing bad' in any case should a future version of PyQt5 not even
# need this.
binaries = []
dylibs_in_pyqt5 = collect_dynamic_libs('PyQt5', 'DUMMY_NOT_USED')
for tuple in dylibs_in_pyqt5:
    # find libqmacstyle.dylib ...
    if "libqmacstyle.dylib" in tuple[0]:
        # .. and include all the .dylibs in that dir in our 'binaries' PyInstaller spec
        binaries += [( os.path.dirname(tuple[0]) + '/*.dylib', 'PyQt5/Qt/plugins/styles' )]
        break

# We don't put these files in to actually include them in the script but to make the Analysis method scan them for imports
a = Analysis([electrum+MAIN_SCRIPT,
              electrum+'gui/qt/main_window.py',
              electrum+'gui/text.py',
              electrum+'lib/util.py',
              electrum+'lib/wallet.py',
              electrum+'lib/simple_config.py',
              electrum+'lib/bitcoin.py',
              electrum+'lib/dnssec.py',
              electrum+'lib/commands.py',
              electrum+'plugins/cosigner_pool/qt.py',
              electrum+'plugins/email_requests/qt.py',
              electrum+'plugins/trezor/client.py',
              electrum+'plugins/trezor/qt.py',
              electrum+'plugins/keepkey/qt.py',
              electrum+'plugins/ledger/qt.py',
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
             info_plist = {
                 'NSHighResolutionCapable':'True'
             }
)
