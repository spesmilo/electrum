from i18n import _
from PyQt4.QtGui import *
from PyQt4.QtCore import *

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

