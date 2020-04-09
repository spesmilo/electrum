# -*- mode: python -*-

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, collect_dynamic_libs

import sys
for i, x in enumerate(sys.argv):
    if x == '--name':
        cmdline_name = sys.argv[i+1]
        break
else:
    raise Exception('no name')

PYHOME = 'c:/python3'

home = 'C:\\electrumsys\\'

# see https://github.com/pyinstaller/pyinstaller/issues/2005
hiddenimports = []
hiddenimports += collect_submodules('pkg_resources')  # workaround for https://github.com/pypa/setuptools/issues/1963
hiddenimports += collect_submodules('trezorlib')
hiddenimports += collect_submodules('safetlib')
hiddenimports += collect_submodules('btchip')
hiddenimports += collect_submodules('keepkeylib')
hiddenimports += collect_submodules('websocket')
hiddenimports += collect_submodules('ckcc')
hiddenimports += ['PyQt5.QtPrintSupport']  # needed by Revealer


binaries = []

# Workaround for "Retro Look":
binaries += [b for b in collect_dynamic_libs('PyQt5') if 'qwindowsvista' in b[0]]

binaries += [('C:/tmp/libsecp256k1-0.dll', '.')]
binaries += [('C:/tmp/libusb-1.0.dll', '.')]

datas = [
    (home+'electrumsys/*.json', 'electrumsys'),
    (home+'electrumsys/lnwire/*.csv', 'electrumsys/lnwire'),
    (home+'electrumsys/wordlist/english.txt', 'electrumsys/wordlist'),
    (home+'electrumsys/locale', 'electrumsys/locale'),
    (home+'electrumsys/plugins', 'electrumsys/plugins'),
    ('C:\\Program Files (x86)\\ZBar\\bin\\', '.'),
    (home+'electrumsys/gui/icons', 'electrumsys/gui/icons'),
    (home+'electrumsys/lnwire', 'electrumsys/lnwire'),
]
datas += collect_data_files('trezorlib')
datas += collect_data_files('safetlib')
datas += collect_data_files('btchip')
datas += collect_data_files('keepkeylib')
datas += collect_data_files('ckcc')
datas += collect_data_files('jsonrpcserver')
datas += collect_data_files('jsonrpcclient')

# We don't put these files in to actually include them in the script but to make the Analysis method scan them for imports
a = Analysis([home+'run_electrumsys',
              home+'electrumsys/gui/qt/main_window.py',
              home+'electrumsys/gui/text.py',
              home+'electrumsys/util.py',
              home+'electrumsys/wallet.py',
              home+'electrumsys/simple_config.py',
              home+'electrumsys/bitcoin.py',
              home+'electrumsys/dnssec.py',
              home+'electrumsys/commands.py',
              home+'electrumsys/plugins/cosigner_pool/qt.py',
              home+'electrumsys/plugins/email_requests/qt.py',
              home+'electrumsys/plugins/trezor/qt.py',
              home+'electrumsys/plugins/safe_t/client.py',
              home+'electrumsys/plugins/safe_t/qt.py',
              home+'electrumsys/plugins/keepkey/qt.py',
              home+'electrumsys/plugins/ledger/qt.py',
              home+'electrumsys/plugins/coldcard/qt.py',
              #home+'packages/requests/utils.py'
              ],
             binaries=binaries,
             datas=datas,
             #pathex=[home+'lib', home+'gui', home+'plugins'],
             hiddenimports=hiddenimports,
             hookspath=[])


# http://stackoverflow.com/questions/19055089/pyinstaller-onefile-warning-pyconfig-h-when-importing-scipy-or-scipy-signal
for d in a.datas:
    if 'pyconfig' in d[0]:
        a.datas.remove(d)
        break

# Strip out parts of Qt that we never use. Reduces binary size by tens of MBs. see #4815
qt_bins2remove=('qt5web', 'qt53d', 'qt5game', 'qt5designer', 'qt5quick',
                'qt5location', 'qt5test', 'qt5xml', r'pyqt5\qt\qml\qtquick')
print("Removing Qt binaries:", *qt_bins2remove)
for x in a.binaries.copy():
    for r in qt_bins2remove:
        if x[0].lower().startswith(r):
            a.binaries.remove(x)
            print('----> Removed x =', x)

qt_data2remove=(r'pyqt5\qt\translations\qtwebengine_locales', )
print("Removing Qt datas:", *qt_data2remove)
for x in a.datas.copy():
    for r in qt_data2remove:
        if x[0].lower().startswith(r):
            a.datas.remove(x)
            print('----> Removed x =', x)

# hotfix for #3171 (pre-Win10 binaries)
a.binaries = [x for x in a.binaries if not x[1].lower().startswith(r'c:\windows')]

pyz = PYZ(a.pure)


#####
# "standalone" exe with all dependencies packed into it

exe_standalone = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name=os.path.join('build\\pyi.win32\\electrumsys', cmdline_name + ".exe"),
    debug=False,
    strip=None,
    upx=False,
    icon=home+'electrumsys/gui/icons/electrumsys.ico',
    console=False)
    # console=True makes an annoying black box pop up, but it does make ElectrumSys output command line commands, with this turned off no output will be given but commands can still be used

exe_portable = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas + [ ('is_portable', 'README.md', 'DATA' ) ],
    name=os.path.join('build\\pyi.win32\\electrumsys', cmdline_name + "-portable.exe"),
    debug=False,
    strip=None,
    upx=False,
    icon=home+'electrumsys/gui/icons/electrumsys.ico',
    console=False)

#####
# exe and separate files that NSIS uses to build installer "setup" exe

exe_dependent = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name=os.path.join('build\\pyi.win32\\electrumsys', cmdline_name),
    debug=False,
    strip=None,
    upx=False,
    icon=home+'electrumsys/gui/icons/electrumsys.ico',
    console=False)

coll = COLLECT(
    exe_dependent,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=None,
    upx=True,
    debug=False,
    icon=home+'electrumsys/gui/icons/electrumsys.ico',
    console=False,
    name=os.path.join('dist', 'electrumsys'))
