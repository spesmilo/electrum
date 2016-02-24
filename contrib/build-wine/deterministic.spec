# -*- mode: python -*-

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
              home+'plugins/trezor/qt.py',
              home+'plugins/keepkey/qt.py',
              home+'plugins/ledger/qt.py',
              home+'packages/requests/utils.py'
              ],
             pathex=[home+'lib', home+'gui', home+'plugins', home+'packages'],
             hiddenimports=['lib', 'gui'],
             hookspath=[])

##### include folder in distribution #######
def extra_datas(mydir):
    def rec_glob(p, files):
        import os
        import glob
        for d in glob.glob(p):
            if os.path.isfile(d):
                files.append(d)
            rec_glob("%s/*" % d, files)
    files = []
    rec_glob("%s/*" % mydir, files)
    extra_datas = []
    for f in files:
        d = f.split('\\')
        t = ''
        for a in d[2:]:
            if len(t)==0:
                t = a
            else:
                t = t+'\\'+a
        extra_datas.append((t, f, 'DATA'))

    return extra_datas
###########################################

# append dirs

# cacert.pem
a.datas += [ ('requests/cacert.pem', home+'packages/requests/cacert.pem', 'DATA') ]

# Py folders that are needed because of the magic import finding
a.datas += extra_datas(home+'gui')
a.datas += extra_datas(home+'lib')
a.datas += extra_datas(home+'plugins')
a.datas += extra_datas(home+'packages')

pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.datas,
          name=os.path.join('build\\pyi.win32\\electrum', 'electrum.exe'),
          debug=False,
          strip=None,
          upx=False,
          icon=home+'icons/electrum.ico',
          console=False)
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
