from electrum.i18n import _
from PyQt4.QtGui import *
from PyQt4.QtCore import *
import os.path
import time


class Timer(QThread):
    def run(self):
        while True:
            self.emit(SIGNAL('timersignal'))
            time.sleep(0.5)


class EnterButton(QPushButton):
    def __init__(self, text, func):
        QPushButton.__init__(self, text)
        self.func = func
        self.clicked.connect(func)

    def keyPressEvent(self, e):
        if e.key() == Qt.Key_Return:
            apply(self.func,())


def waiting_dialog(f, w=None):

    s = Timer()
    s.start()
    if not w:
        w = QDialog()
        w.resize(200, 70)
        w.setWindowTitle('Electrum')
    else:
        if w.layout(): QWidget().setLayout(w.layout())

    l = QLabel('')
    vbox = QVBoxLayout(w)
    vbox.addWidget(l)
    w.show()
    def ff():
        s = f()
        if s: l.setText(s)
        else: w.accept()
    w.connect(s, SIGNAL('timersignal'), ff)
    w.exec_()
    #w.destroy()


class HelpButton(QPushButton):
    def __init__(self, text):
        QPushButton.__init__(self, '?')
        self.setFocusPolicy(Qt.NoFocus)
        self.setFixedWidth(20)
        self.clicked.connect(lambda: QMessageBox.information(self, 'Help', text, 'OK') )



def backup_wallet(path):
    import shutil
    directory, fileName = os.path.split(path)
    try:
        otherpath = unicode( QFileDialog.getOpenFileName(QWidget(), _('Enter a filename for the copy of your wallet'), directory) )
        if otherpath and path!=otherpath:
            shutil.copy2(path, otherpath)
            QMessageBox.information(None,"Wallet backup created", _("A copy of your wallet file was created in")+" '%s'" % str(otherpath))
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

