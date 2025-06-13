# -*- mode: python -*-
import sys
import os
from typing import TYPE_CHECKING

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, collect_dynamic_libs, copy_metadata

if TYPE_CHECKING:
    from PyInstaller.building.build_main import Analysis, PYZ, EXE, COLLECT


PYPKG="electrum"
MAIN_SCRIPT="run_electrum"
PROJECT_ROOT = "C:/electrum"
ICONS_FILE=f"{PROJECT_ROOT}/{PYPKG}/gui/icons/electrum.ico"

cmdline_name = os.environ.get("ELECTRUM_CMDLINE_NAME")
if not cmdline_name:
    raise Exception('no name')


# see https://github.com/pyinstaller/pyinstaller/issues/2005
hiddenimports = []
hiddenimports += collect_submodules('pkg_resources')  # workaround for https://github.com/pypa/setuptools/issues/1963
hiddenimports += collect_submodules(f"{PYPKG}.plugins")


binaries = []
# Workaround for "Retro Look":
binaries += [b for b in collect_dynamic_libs('PyQt6') if 'qwindowsvista' in b[0]]
# add libsecp256k1, libusb, etc:
binaries += [(f"{PROJECT_ROOT}/{PYPKG}/*.dll", '.')]


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
    name=os.path.join("build", "pyi.win32", PYPKG, f"{cmdline_name}.exe"),
    debug=False,
    strip=None,
    upx=False,
    icon=ICONS_FILE,
    console=False)
    # console=True makes an annoying black box pop up, but it does make Electrum output command line commands, with this turned off no output will be given but commands can still be used

exe_portable = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas + [('is_portable', 'README.md', 'DATA')],
    name=os.path.join("build", "pyi.win32", PYPKG, f"{cmdline_name}-portable.exe"),
    debug=False,
    strip=None,
    upx=False,
    icon=ICONS_FILE,
    console=False)

#####
# exe and separate files that NSIS uses to build installer "setup" exe

exe_inside_setup_noconsole = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name=os.path.join("build", "pyi.win32", PYPKG, f"{cmdline_name}.exe"),
    debug=False,
    strip=None,
    upx=False,
    icon=ICONS_FILE,
    console=False)

exe_inside_setup_console = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name=os.path.join("build", "pyi.win32", PYPKG, f"{cmdline_name}-debug.exe"),
    debug=False,
    strip=None,
    upx=False,
    icon=ICONS_FILE,
    console=True)

coll = COLLECT(
    exe_inside_setup_noconsole,
    exe_inside_setup_console,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=None,
    upx=True,
    debug=False,
    icon=ICONS_FILE,
    console=False,
    name=os.path.join('dist', PYPKG))
