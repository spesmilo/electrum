# -*- mode: python -*-
import sys
import os
from typing import TYPE_CHECKING

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, collect_dynamic_libs, copy_metadata

if TYPE_CHECKING:
    from PyInstaller.building.build_main import Analysis, PYZ, EXE, BUNDLE


PACKAGE_NAME='Electrum.app'
PYPKG='electrum'
MAIN_SCRIPT='run_electrum'
PROJECT_ROOT = os.path.abspath(".")
ICONS_FILE=f"{PROJECT_ROOT}/{PYPKG}/gui/icons/electrum.icns"


VERSION = os.environ.get("ELECTRUM_VERSION")
if not VERSION:
    raise Exception('no version')

block_cipher = None

# see https://github.com/pyinstaller/pyinstaller/issues/2005
hiddenimports = []
hiddenimports += collect_submodules('pkg_resources')  # workaround for https://github.com/pypa/setuptools/issues/1963
hiddenimports += collect_submodules(f"{PYPKG}.plugins")


binaries = []
# Workaround for "Retro Look":
binaries += [b for b in collect_dynamic_libs('PyQt6') if 'macstyle' in b[0]]
# add libsecp256k1, libusb, etc:
binaries += [(f"{PROJECT_ROOT}/{PYPKG}/*.dylib", ".")]


datas = [
    (f"{PROJECT_ROOT}/{PYPKG}/*.json", PYPKG),
    (f"{PROJECT_ROOT}/{PYPKG}/lnwire/*.csv", f"{PYPKG}/lnwire"),
    (f"{PROJECT_ROOT}/{PYPKG}/wordlist/english.txt", f"{PYPKG}/wordlist"),
    (f"{PROJECT_ROOT}/{PYPKG}/wordlist/slip39.txt", f"{PYPKG}/wordlist"),
    (f"{PROJECT_ROOT}/{PYPKG}/chains", f"{PYPKG}/chains"),
    (f"{PROJECT_ROOT}/{PYPKG}/locale", f"{PYPKG}/locale"),
    (f"{PROJECT_ROOT}/{PYPKG}/plugins", f"{PYPKG}/plugins"),
    (f"{PROJECT_ROOT}/{PYPKG}/gui/icons", f"{PYPKG}/gui/icons"),
    (f"{PROJECT_ROOT}/{PYPKG}/gui/fonts", f"{PYPKG}/gui/fonts"),
]
datas += collect_data_files(f"{PYPKG}.plugins")
datas += collect_data_files('trezorlib')  # TODO is this needed? and same question for other hww libs
datas += collect_data_files('safetlib')
datas += collect_data_files('ckcc')
datas += collect_data_files('bitbox02')

# some deps rely on importlib metadata
datas += copy_metadata('slip10')  # from trezor->slip10

# Exclude parts of Qt that we never use. Reduces binary size by tens of MBs. see #4815
excludes = [
    "PyQt6.QtBluetooth",
    "PyQt6.QtDesigner",
    "PyQt6.QtNfc",
    "PyQt6.QtPositioning",
    "PyQt6.QtQml",
    "PyQt6.QtQuick",
    "PyQt6.QtQuick3D",
    "PyQt6.QtQuickWidgets",
    "PyQt6.QtRemoteObjects",
    "PyQt6.QtSensors",
    "PyQt6.QtSerialPort",
    "PyQt6.QtSpatialAudio",
    "PyQt6.QtSql",
    "PyQt6.QtTest",
    "PyQt6.QtTextToSpeech",
    "PyQt6.QtWebChannel",
    "PyQt6.QtWebSockets",
    "PyQt6.QtXml",
    # "PyQt6.QtNetwork",  # needed by QtMultimedia. kinda weird but ok.
]

# We don't put these files in to actually include them in the script but to make the Analysis method scan them for imports
a = Analysis([f"{PROJECT_ROOT}/{MAIN_SCRIPT}",
              f"{PROJECT_ROOT}/{PYPKG}/gui/qt/main_window.py",
              f"{PROJECT_ROOT}/{PYPKG}/gui/qt/qrreader/qtmultimedia/camera_dialog.py",
              f"{PROJECT_ROOT}/{PYPKG}/gui/text.py",
              f"{PROJECT_ROOT}/{PYPKG}/util.py",
              f"{PROJECT_ROOT}/{PYPKG}/wallet.py",
              f"{PROJECT_ROOT}/{PYPKG}/simple_config.py",
              f"{PROJECT_ROOT}/{PYPKG}/bitcoin.py",
              f"{PROJECT_ROOT}/{PYPKG}/dnssec.py",
              f"{PROJECT_ROOT}/{PYPKG}/commands.py",
              ],
             binaries=binaries,
             datas=datas,
             hiddenimports=hiddenimports,
             hookspath=[],
             excludes=excludes,
             )


# http://stackoverflow.com/questions/19055089/pyinstaller-onefile-warning-pyconfig-h-when-importing-scipy-or-scipy-signal
for d in a.datas:
    if 'pyconfig' in d[0]:
        a.datas.remove(d)
        break


pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name=MAIN_SCRIPT,
    debug=False,
    strip=False,
    upx=True,
    icon=ICONS_FILE,
    console=False,
    target_arch='x86_64',  # TODO investigate building 'universal2'
)

app = BUNDLE(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    version=VERSION,
    name=PACKAGE_NAME,
    icon=ICONS_FILE,
    bundle_identifier=None,
    info_plist={
        'NSHighResolutionCapable': 'True',
        'NSSupportsAutomaticGraphicsSwitching': 'True',
        'CFBundleURLTypes':
            [{
                'CFBundleURLName': 'bitcoin',
                'CFBundleURLSchemes': ['bitcoin', 'lightning', ],
            }],
        'LSMinimumSystemVersion': '11',
        'NSCameraUsageDescription': 'Electrum would like to access the camera to scan for QR codes',
    },
)
