# -*- mode: python -*-
a = Analysis(['C:/electrum/electrum'],
             pathex=['Z:\\electrum-wine'],
             hiddenimports=[],
             excludes=['Tkinter'],
             hookspath=None)
pyz = PYZ(a.pure, level=0)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=1,
          name=os.path.join('build\\pyi.win32\\electrum', 'electrum.exe'),
          debug=False,
          strip=None,
          upx=True,
          console=False )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=None,
               upx=True,
               name=os.path.join('dist', 'electrum'))
app = BUNDLE(coll,
             name=os.path.join('dist', 'electrum.app'))
