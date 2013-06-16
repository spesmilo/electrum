from i18n import _
from PyQt4.QtGui import *
from PyQt4.QtCore import *
import os.path

def backup_wallet():
    try:
      folderName = QFileDialog.getExistingDirectory(QWidget(), _('Select folder to save a copy of your wallet to'), os.path.expanduser('~/'))
      if folderName:
        # TODO: Can we get the current wallet file instead of bruteforcing the default one?
        sourceFile = self.wallet.config.path
        shutil.copy2(sourceFile, str(folderName))
        QMessageBox.information(None,"Wallet backup created", _("A copy of your wallet file was created in")+" '%s'" % str(folderName))
    except (IOError, os.error), reason:
      QMessageBox.critical(None,"Unable to create backup", _("Electrum was unable to copy your wallet file to the specified location.")+"\n" + str(reason))

def ok_cancel_buttons(dialog, ok_label=_("OK") ):
    hbox = QHBoxLayout()
    hbox.addStretch(1)
    b = QPushButton(_("Cancel"))
    hbox.addWidget(b)
    b.clicked.connect(dialog.reject)
    b = QPushButton(ok_label)
    hbox.addWidget(b)
    b.clicked.connect(dialog.accept)
    b.setDefault(True)
    return hbox

def text_dialog(parent, title, label, ok_label):
    dialog = QDialog(parent)
    dialog.setMinimumWidth(500)
    dialog.setWindowTitle(title)
    dialog.setModal(1)
    l = QVBoxLayout()
    dialog.setLayout(l)
    l.addWidget(QLabel(label))
    txt = QTextEdit()
    l.addWidget(txt)
    l.addLayout(ok_cancel_buttons(dialog, ok_label))
    if dialog.exec_():
        return unicode(txt.toPlainText())

