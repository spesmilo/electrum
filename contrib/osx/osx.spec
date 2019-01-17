# -*- mode: python -*-

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, collect_dynamic_libs
import sys, os

PACKAGE='Electron-Cash'
BUNDLE_IDENTIFIER='org.electroncash.' + PACKAGE # Used for info.plist 
PYPKG='electroncash'
MAIN_SCRIPT='electron-cash'
ICONS_FILE='electron.icns'
APP_SIGN = os.environ.get('APP_SIGN', '')

def fail(*msg):
    RED='\033[0;31m'
    NC='\033[0m' # No Color
    print("\r🗯 {}ERROR:{}".format(RED, NC), *msg)
    sys.exit(1)

def codesign(identity, binary):
    d = os.path.dirname(binary)
    saved_dir=None
    if d:
        # switch to directory of the binary so codesign verbose messages don't include long path
        saved_dir = os.path.abspath(os.path.curdir)
        os.chdir(d)
        binary = os.path.basename(binary)
    os.system("codesign -v -f -s '{}' '{}'".format(identity, binary))==0 or fail("Could not code sign " + binary)
    if saved_dir:
        os.chdir(saved_dir)

def monkey_patch_pyinstaller_for_codesigning(identity):
    # Monkey-patch PyInstaller so that we app-sign all binaries *after* they are modified by PyInstaller
    # If we app-sign before that point, the signature will be invalid because PyInstaller modifies
    # @loader_path in the Mach-O loader table.
    try:
        import PyInstaller.depend.dylib
        _saved_func = PyInstaller.depend.dylib.mac_set_relative_dylib_deps
    except (ImportError, NameError, AttributeError):
        # Hmm. Likely wrong PyInstaller version.
        fail("Could not monkey-patch PyInstaller for code signing. Please ensure that you are using PyInstaller 3.4.")
    _signed = set()
    def my_func(fn, distname):
        _saved_func(fn, distname)
        if  (fn, distname) not in _signed:
            codesign(identity, fn)
            _signed.add((fn,distname)) # remember we signed it so we don't sign again
    PyInstaller.depend.dylib.mac_set_relative_dylib_deps = my_func


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

# Add the QR Scanner helper app
datas += [(home + "contrib/osx/CalinsQRReader/build/Release/CalinsQRReader.app", "./contrib/osx/CalinsQRReader/build/Release/CalinsQRReader.app")]

# Add libusb so Trezor will work
binaries = [(home + "contrib/osx/libusb-1.0.dylib", ".")]
binaries += [(home + "contrib/osx/libsecp256k1.0.dylib", ".")]

# Workaround for "Retro Look":
binaries += [b for b in collect_dynamic_libs('PyQt5') if 'macstyle' in b[0]]

# We don't put these files in to actually include them in the script but to make the Analysis method scan them for imports
a = Analysis([home+MAIN_SCRIPT,
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
              home+'plugins/trezor/clientbase.py',
              home+'plugins/trezor/trezor.py',
              home+'plugins/trezor/qt.py',
              home+'plugins/keepkey/qt.py',
              home+'plugins/ledger/qt.py',
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
bins2remove=('qtweb', 'qt3d', 'qtgame', 'qtdesigner', 'qtquick', 'qtlocation', 'qttest', 'qtxml')
files2remove=('libqsqlmysql.dylib', 'libdeclarative_multimedia.dylib', 'libqtquickscene2dplugin.dylib', 'libqtquickscene3dplugin.dylib')
print("Removing", *(bins2remove + files2remove))
for x in a.binaries.copy():
    for r in bins2remove:
        if x[0].lower().startswith(r) or os.path.basename(x[1].lower()) in files2remove:
            a.binaries.remove(x)
            print('----> Removed:', x)
            break # break from inner loop
#

# If code signing, monkey-patch in a code signing step to pyinstaller. See: https://github.com/spesmilo/electrum/issues/4994
if APP_SIGN:
    monkey_patch_pyinstaller_for_codesigning(APP_SIGN)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.datas,
          name=PACKAGE,
          debug=False,
          strip=False,
          upx=True,
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
