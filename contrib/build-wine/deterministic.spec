# -*- mode: python -*-

import sys
for i, x in enumerate(sys.argv):
    if x == '--name':
        cmdline_name = sys.argv[i+1]
        break
else:
    raise BaseException('no name')


home = 'C:\\electrum\\'

# We don't put these files in to actually include them in the script but to make the Analysis method scan them for imports
a = Analysis([home+'electrum',
              home+'gui/qt/main_window.py',
              home+'gui/text.py',
              home+'lib/util.py',
              home+'lib/wallet.py',
              home+'lib/simple_config.py',
              home+'lib/bitcoin.py',
              home+'lib/dnssec.py',
              home+'lib/commands.py',
              home+'plugins/cosigner_pool/qt.py',
              home+'plugins/email_requests/qt.py',
              home+'plugins/trezor/client.py',
              home+'plugins/trezor/qt.py',
              home+'plugins/keepkey/qt.py',
              home+'plugins/ledger/qt.py',
              #home+'packages/requests/utils.py'
              ],
             datas = [
                 (home+'lib/currencies.json', 'electrum'),
                 (home+'lib/wordlist/english.txt', 'electrum/wordlist'),
                 #(home+'packages/requests/cacert.pem', 'requests/cacert.pem')
             ],
             #pathex=[home+'lib', home+'gui', home+'plugins'],
             #hiddenimports=["lib", "gui", "plugins", "electrum_gui.qt.icons_rc"],
             hookspath=[])


# http://stackoverflow.com/questions/19055089/pyinstaller-onefile-warning-pyconfig-h-when-importing-scipy-or-scipy-signal
for d in a.datas:
    if 'pyconfig' in d[0]: 
        a.datas.remove(d)
        break

pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.datas,
          name=os.path.join('build\\pyi.win32\\electrum', cmdline_name),
          debug=False,
          strip=None,
          upx=False,
          icon=home+'icons/electrum.ico',
          console=True)
          # The console True makes an annoying black box pop up, but it does make Electrum output command line commands, with this turned off no output will be given but commands can still be used

coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=None,
               upx=True,
               debug=False,
               icon=home+'icons/electrum.ico',
               console=False,
               name=os.path.join('dist', 'electrum'))
