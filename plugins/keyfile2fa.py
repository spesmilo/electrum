from PyQt4.QtGui import *
from PyQt4.QtCore import *
from electrum.plugins import BasePlugin, hook
from electrum.i18n import _

import hashlib

class Plugin(BasePlugin):

    def fullname(self):
        return 'Key File 2FA Support'

    def description(self):
        return '%s\n%s' % (_("Add an optional key file chooser to the password dialog."), _("This protects against key loggers but not more sophisticated malware targeting Electrum."))
 
    def mkpwdkey(self):
        if self.keyfiles[0] != None:
            data = ''
            with open(self.keyfiles[0], "r") as kf:
                data = kf.read()
            self.pwds[0].setText(str( self.pwds[0].text() ) + hashlib.sha256(data).digest().encode('hex'))
        if len(self.keyfiles) > 1 and self.keyfiles[1] != None:
            data = ''
            with open(self.keyfiles[1], "r") as kf:
                data = kf.read()
            keytext = hashlib.sha256(data).digest().encode('hex')
            self.pwds[1].setText(str( self.pwds[1].text() ) + keytext)
            self.pwds[2].setText(str( self.pwds[2].text() ) + keytext)
 
    def findOKBtn(self, layout):
        for i in range(layout.count()): 
            if type(layout.itemAt(i).widget()) == QPushButton and layout.itemAt(i).widget().isDefault():
                return layout.itemAt(i).widget()
            if layout.itemAt(i).layout() != None:
                rtn = self.findOKBtn(layout.itemAt(i).layout())
                if rtn != None:
                    return rtn
        return None

    @hook
    def password_dialog(self, pwd, grid, pos):
        self.pwds = [ pwd ]
        self.keyfiles = [ None ]
        okBtn = self.findOKBtn(grid.parent())
        okBtn.clicked.connect(self.mkpwdkey)
        keyBtn = QPushButton( QIcon(":icons/key.png"),'' )
        keyBtn.setIconSize(QSize(16,16))
        keyBtn.clicked.connect(lambda: self.get_keyfile(pwd, 0))
        grid.addWidget(keyBtn, pos, grid.columnCount()+1)
 
    @hook
    def new_password_dialog(self, pwds, grid, pos, chg_pass):
        self.pwds = pwds
        self.keyfiles = [ None for x in pwds ]
        okBtn = self.findOKBtn(grid.parent())
        okBtn.clicked.connect(self.mkpwdkey)
        col = grid.columnCount()+1
        if chg_pass:
            keyBtn = QPushButton( QIcon(":icons/key.png"),'' )
            keyBtn.setIconSize(QSize(16,16))
            keyBtn.clicked.connect(lambda: self.get_keyfile(pwds[0], 0))
            grid.addWidget(keyBtn, pos, col)        
        keyBtnN = QPushButton( QIcon(":icons/key.png"),'' )
        keyBtnN.setIconSize(QSize(16,16))
        keyBtnN.clicked.connect(lambda: self.get_keyfile(pwds[1], 1))
        grid.addWidget(keyBtnN, pos+1, col)
        
    def get_keyfile(self, pw, n):
        self.keyfiles[n] = unicode( QFileDialog.getOpenFileName(pw, "Select your key file", '') )
        
    


