from electrum.i18n import _
from PyQt4.QtGui import *
from PyQt4.QtCore import *
import os.path
import time
import traceback
import sys
import threading
import platform

if platform.system() == 'Windows':
    MONOSPACE_FONT = 'Lucida Console'
elif platform.system() == 'Darwin':
    MONOSPACE_FONT = 'Monaco'
else:
    MONOSPACE_FONT = 'monospace'


class WaitingDialog(QThread):
    def __init__(self, parent, message, run_task, on_success=None, on_complete=None):
        QThread.__init__(self)
        self.parent = parent
        self.d = QDialog(parent)
        self.d.setWindowTitle('Please wait')
        l = QLabel(message)
        vbox = QVBoxLayout(self.d)
        vbox.addWidget(l)
        self.run_task = run_task
        self.on_success = on_success
        self.on_complete = on_complete
        self.d.connect(self.d, SIGNAL('done'), self.close)
        self.d.show()

    def run(self):
        self.error = None
        try:
            self.result = self.run_task()
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            self.error = str(e)
        self.d.emit(SIGNAL('done'))

    def close(self):
        self.d.accept()
        if self.error:
            QMessageBox.warning(self.parent, _('Error'), self.error, _('OK'))
        else:
            if self.on_success:
                if type(self.result) is not tuple:
                    self.result = (self.result,)
                self.on_success(*self.result)

        if self.on_complete:
            self.on_complete()


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


class ThreadedButton(QPushButton):
    def __init__(self, text, func, on_success=None):
        QPushButton.__init__(self, text)
        self.run_task = func
        self.on_success = on_success
        self.clicked.connect(self.do_exec)
        self.connect(self, SIGNAL('done'), self.done)
        self.connect(self, SIGNAL('error'), self.on_error)

    def done(self):
        if self.on_success:
            self.on_success()
        self.setEnabled(True)

    def on_error(self):
        QMessageBox.information(None, _("Error"), self.error)
        self.setEnabled(True)

    def do_func(self):
        self.setEnabled(False)
        try:
            self.result = self.run_task()
        except BaseException as e:
            self.error = str(e.message)
            self.emit(SIGNAL('error'))
            return
        self.emit(SIGNAL('done'))

    def do_exec(self):
        t = threading.Thread(target=self.do_func)
        t.setDaemon(True)
        t.start()


class HelpButton(QPushButton):
    def __init__(self, text):
        QPushButton.__init__(self, '?')
        self.help_text = text
        self.setFocusPolicy(Qt.NoFocus)
        self.setFixedWidth(20)
        self.alt = None
        self.clicked.connect(self.onclick)

    def set_alt(self, func):
        self.alt = func

    def onclick(self):
        if self.alt:
            apply(self.alt)
        else:
            QMessageBox.information(self, 'Help', self.help_text, 'OK')

class Buttons(QHBoxLayout):
    def __init__(self, *buttons):
        QHBoxLayout.__init__(self)
        self.addStretch(1)
        for b in buttons:
            self.addWidget(b)

class CloseButton(QPushButton):
    def __init__(self, dialog):
        QPushButton.__init__(self, _("Close"))
        self.clicked.connect(dialog.close)
        self.setDefault(True)

class CopyButton(QPushButton):
    def __init__(self, text, app):
        QPushButton.__init__(self, _("Copy"))
        self.clicked.connect(lambda: app.clipboard().setText(str(text.toPlainText())))

class OkButton(QPushButton):
    def __init__(self, dialog, label=None):
        QPushButton.__init__(self, label or _("OK"))
        self.clicked.connect(dialog.accept)
        self.setDefault(True)

class CancelButton(QPushButton):
    def __init__(self, dialog, label=None):
        QPushButton.__init__(self, label or _("Cancel"))
        self.clicked.connect(dialog.reject)


def line_dialog(parent, title, label, ok_label, default=None):
    dialog = QDialog(parent)
    dialog.setMinimumWidth(500)
    dialog.setWindowTitle(title)
    dialog.setModal(1)
    l = QVBoxLayout()
    dialog.setLayout(l)
    l.addWidget(QLabel(label))
    txt = QLineEdit()
    if default:
        txt.setText(default)
    l.addWidget(txt)
    l.addLayout(Buttons(CancelButton(dialog), OkButton(dialog, ok_label)))
    if dialog.exec_():
        return unicode(txt.text())

def text_dialog(parent, title, label, ok_label, default=None):
    from qrtextedit import ScanQRTextEdit
    dialog = QDialog(parent)
    dialog.setMinimumWidth(500)
    dialog.setWindowTitle(title)
    dialog.setModal(1)
    l = QVBoxLayout()
    dialog.setLayout(l)
    l.addWidget(QLabel(label))
    txt = ScanQRTextEdit(parent)
    if default:
        txt.setText(default)
    l.addWidget(txt)
    l.addLayout(Buttons(CancelButton(dialog), OkButton(dialog, ok_label)))
    if dialog.exec_():
        return unicode(txt.toPlainText())

def question(msg):
    return QMessageBox.question(None, _('Message'), msg, QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes

def address_field(addresses):
    hbox = QHBoxLayout()
    address_e = QLineEdit()
    if addresses:
        address_e.setText(addresses[0])
    def func():
        i = addresses.index(str(address_e.text())) + 1
        i = i % len(addresses)
        address_e.setText(addresses[i])
    button = QPushButton(_('Address'))
    button.clicked.connect(func)
    hbox.addWidget(button)
    hbox.addWidget(address_e)
    return hbox, address_e


def filename_field(parent, config, defaultname, select_msg):

    vbox = QVBoxLayout()
    vbox.addWidget(QLabel(_("Format")))
    gb = QGroupBox("format", parent)
    b1 = QRadioButton(gb)
    b1.setText(_("CSV"))
    b1.setChecked(True)
    b2 = QRadioButton(gb)
    b2.setText(_("json"))
    vbox.addWidget(b1)
    vbox.addWidget(b2)

    hbox = QHBoxLayout()

    directory = config.get('io_dir', unicode(os.path.expanduser('~')))
    path = os.path.join( directory, defaultname )
    filename_e = QLineEdit()
    filename_e.setText(path)

    def func():
        text = unicode(filename_e.text())
        _filter = "*.csv" if text.endswith(".csv") else "*.json" if text.endswith(".json") else None
        p = unicode( QFileDialog.getSaveFileName(None, select_msg, text, _filter))
        if p:
            filename_e.setText(p)

    button = QPushButton(_('File'))
    button.clicked.connect(func)
    hbox.addWidget(button)
    hbox.addWidget(filename_e)
    vbox.addLayout(hbox)

    def set_csv(v):
        text = unicode(filename_e.text())
        text = text.replace(".json",".csv") if v else text.replace(".csv",".json")
        filename_e.setText(text)

    b1.clicked.connect(lambda: set_csv(True))
    b2.clicked.connect(lambda: set_csv(False))

    return vbox, filename_e, b1



class MyTreeWidget(QTreeWidget):

    def __init__(self, parent):
        QTreeWidget.__init__(self, parent)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.itemActivated.connect(self.on_activated)
        # extend the syntax for consistency
        self.addChild = self.addTopLevelItem
        self.insertChild = self.insertTopLevelItem

    def on_activated(self, item):
        if not item: return
        for i in range(0,self.viewport().height()/5):
            if self.itemAt(QPoint(0,i*5)) == item:
                break
        else:
            return
        for j in range(0,30):
            if self.itemAt(QPoint(0,i*5 + j)) != item:
                break
        self.emit(SIGNAL('customContextMenuRequested(const QPoint&)'), QPoint(50, i*5 + j - 1))




if __name__ == "__main__":
    app = QApplication([])
    t = WaitingDialog(None, 'testing ...', lambda: [time.sleep(1)], lambda x: QMessageBox.information(None, 'done', "done", _('OK')))
    t.start()
    app.exec_()
