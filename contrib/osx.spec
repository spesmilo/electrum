# -*- mode: python -*-

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

import sys
import os

for i, x in enumerate(sys.argv):
    if x == '--name':
        VERSION = sys.argv[i+1]
        break
else:
    raise BaseException('no version')

electrum = "../"
block_cipher=None

# see https://github.com/pyinstaller/pyinstaller/issues/2005
hiddenimports = []
hiddenimports += collect_submodules('trezorlib')
hiddenimports += collect_submodules('btchip')
hiddenimports += collect_submodules('keepkeylib')

datas = [
    (electrum+'lib/currencies.json', 'electrum'),
    (electrum+'lib/servers.json', 'electrum'),
    (electrum+'lib/checkpoints.json', 'electrum'),
    (electrum+'lib/servers_testnet.json', 'electrum'),
    (electrum+'lib/checkpoints_testnet.json', 'electrum'),
    (electrum+'lib/wordlist/english.txt', 'electrum/wordlist'),
    (electrum+'lib/locale', 'electrum/locale'),
    (electrum+'plugins', 'electrum_plugins'),
]
datas += collect_data_files('trezorlib')
datas += collect_data_files('btchip')
datas += collect_data_files('keepkeylib')

# We don't put these files in to actually include them in the script but to make the Analysis method scan them for imports
a = Analysis([electrum+'electrum',
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
          name='Electrum',
          debug=False,
          strip=False,
          upx=True,
          icon=electrum+'electrum.icns',
          console=False)

app = BUNDLE(exe,
             version = VERSION,
             name='Electrum.app',
             icon=electrum+'electrum.icns',
             bundle_identifier=None,
             info_plist = {
                 'NSHighResolutionCapable':'True'
             }
)