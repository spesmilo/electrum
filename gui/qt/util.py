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

GREEN_BG = "QWidget {background-color:#80ff80;}"
RED_BG = "QWidget {background-color:#ffcccc;}"
RED_FG = "QWidget {color:red;}"
BLUE_FG = "QWidget {color:blue;}"
BLACK_FG = "QWidget {color:black;}"


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
    stopped = False

    def run(self):
        while not self.stopped:
            self.emit(SIGNAL('timersignal'))
            time.sleep(0.5)

    def stop(self):
        self.stopped = True
        self.wait()

class EnterButton(QPushButton):
    def __init__(self, text, func):
        QPushButton.__init__(self, text)
        self.func = func
        self.clicked.connect(func)

    def keyPressEvent(self, e):
        if e.key() == Qt.Key_Return:
            apply(self.func,())


class ThreadedButton(QPushButton):
    def __init__(self, text, func, on_success=None, before=None):
        QPushButton.__init__(self, text)
        self.before = before
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
            traceback.print_exc(file=sys.stdout)
            self.error = str(e.message)
            self.emit(SIGNAL('error'))
            return
        self.emit(SIGNAL('done'))

    def do_exec(self):
        if self.before:
            self.before()
        t = threading.Thread(target=self.do_func)
        t.setDaemon(True)
        t.start()


class HelpLabel(QLabel):

    def __init__(self, text, help_text):
        QLabel.__init__(self, text)
        self.help_text = help_text
        self.app = QCoreApplication.instance()
        self.font = QFont()

    def mouseReleaseEvent(self, x):
        QMessageBox.information(self, 'Help', self.help_text, 'OK')

    def enterEvent(self, event):
        self.font.setUnderline(True)
        self.setFont(self.font)
        self.app.setOverrideCursor(QCursor(Qt.PointingHandCursor))
        return QLabel.enterEvent(self, event)

    def leaveEvent(self, event):
        self.font.setUnderline(False)
        self.setFont(self.font)
        self.app.setOverrideCursor(QCursor(Qt.ArrowCursor))
        return QLabel.leaveEvent(self, event)


class HelpButton(QPushButton):
    def __init__(self, text):
        QPushButton.__init__(self, '?')
        self.help_text = text
        self.setFocusPolicy(Qt.NoFocus)
        self.setFixedWidth(20)
        self.clicked.connect(self.onclick)

    def onclick(self):
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
    def __init__(self, text_getter, app):
        QPushButton.__init__(self, _("Copy"))
        self.clicked.connect(lambda: app.clipboard().setText(text_getter()))

class CopyCloseButton(QPushButton):
    def __init__(self, text_getter, app, dialog):
        QPushButton.__init__(self, _("Copy and Close"))
        self.clicked.connect(lambda: app.clipboard().setText(text_getter()))
        self.clicked.connect(dialog.close)
        self.setDefault(True)

class OkButton(QPushButton):
    def __init__(self, dialog, label=None):
        QPushButton.__init__(self, label or _("OK"))
        self.clicked.connect(dialog.accept)
        self.setDefault(True)

class CancelButton(QPushButton):
    def __init__(self, dialog, label=None):
        QPushButton.__init__(self, label or _("Cancel"))
        self.clicked.connect(dialog.reject)

class WindowModalDialog(QDialog):
    '''Handy wrapper; window modal dialogs are better for our multi-window
    daemon model as other wallet windows can still be accessed.'''
    def __init__(self, parent, title=None):
        QDialog.__init__(self, parent)
        self.setWindowModality(Qt.WindowModal)
        if title:
            self.setWindowTitle(title)

    @staticmethod
    def warning(*args, **kwargs):
        return WindowModalDialog.msg_box(QMessageBox.Warning, *args, **kwargs)

    @staticmethod
    def msg_box(icon, parent, title, text, buttons=QMessageBox.Ok,
                defaultButton=QMessageBox.NoButton):
        d = QMessageBox(icon, title, text, buttons, parent)
        d.setWindowModality(Qt.WindowModal)
        d.setDefaultButton(defaultButton)
        return d.exec_()

def line_dialog(parent, title, label, ok_label, default=None):
    dialog = WindowModalDialog(parent, title)
    dialog.setMinimumWidth(500)
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
    dialog = WindowModalDialog(parent, title)
    dialog.setMinimumWidth(500)
    l = QVBoxLayout()
    dialog.setLayout(l)
    l.addWidget(QLabel(label))
    txt = ScanQRTextEdit()
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

class ElectrumItemDelegate(QStyledItemDelegate):
    def createEditor(self, parent, option, index):
        return self.parent().createEditor(parent, option, index)

class MyTreeWidget(QTreeWidget):

    def __init__(self, parent, create_menu, headers, stretch_column=None,
                 editable_columns=None):
        QTreeWidget.__init__(self, parent)
        self.parent = parent
        self.stretch_column = stretch_column
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(create_menu)
        self.setUniformRowHeights(True)
        # extend the syntax for consistency
        self.addChild = self.addTopLevelItem
        self.insertChild = self.insertTopLevelItem

        # Control which columns are editable
        self.editor = None
        self.pending_update = False
        if editable_columns is None:
            editable_columns = [stretch_column]
        self.editable_columns = editable_columns
        self.setItemDelegate(ElectrumItemDelegate(self))
        self.itemActivated.connect(self.on_activated)
        self.update_headers(headers)

    def update_headers(self, headers):
        self.setColumnCount(len(headers))
        self.setHeaderLabels(headers)
        self.header().setStretchLastSection(False)
        for col in range(len(headers)):
            sm = QHeaderView.Stretch if col == self.stretch_column else QHeaderView.ResizeToContents
            self.header().setResizeMode(col, sm)

    def editItem(self, item, column):
        if column in self.editable_columns:
            self.editing_itemcol = (item, column, unicode(item.text(column)))
            # Calling setFlags causes on_changed events for some reason
            item.setFlags(item.flags() | Qt.ItemIsEditable)
            QTreeWidget.editItem(self, item, column)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_F2:
            self.on_activated(self.currentItem(), self.currentColumn())
        else:
            QTreeWidget.keyPressEvent(self, event)

    def permit_edit(self, item, column):
        return (column in self.editable_columns
                and self.on_permit_edit(item, column))

    def on_permit_edit(self, item, column):
        return True

    def on_activated(self, item, column):
        if self.permit_edit(item, column):
            self.editItem(item, column)
        else:
            pt = self.visualItemRect(item).bottomLeft()
            pt.setX(50)
            self.emit(SIGNAL('customContextMenuRequested(const QPoint&)'), pt)

    def createEditor(self, parent, option, index):
        self.editor = QStyledItemDelegate.createEditor(self.itemDelegate(),
                                                       parent, option, index)
        self.editor.connect(self.editor, SIGNAL("editingFinished()"),
                            self.editing_finished)
        return self.editor

    def editing_finished(self):
        # Long-time QT bug - pressing Enter to finish editing signals
        # editingFinished twice.  If the item changed the sequence is
        # Enter key:  editingFinished, on_change, editingFinished
        # Mouse: on_change, editingFinished
        # This mess is the cleanest way to ensure we make the
        # on_edited callback with the updated item
        if self.editor:
            (item, column, prior_text) = self.editing_itemcol
            if self.editor.text() == prior_text:
                self.editor = None  # Unchanged - ignore any 2nd call
            elif item.text(column) == prior_text:
                pass # Buggy first call on Enter key, item not yet updated
            else:
                # What we want - the updated item
                self.on_edited(*self.editing_itemcol)
                self.editor = None

            # Now do any pending updates
            if self.editor is None and self.pending_update:
                self.pending_update = False
                self.on_update()

    def on_edited(self, item, column, prior):
        '''Called only when the text actually changes'''
        key = str(item.data(0, Qt.UserRole).toString())
        text = unicode(item.text(column))
        self.parent.wallet.set_label(key, text)
        self.parent.history_list.update()
        self.parent.update_completions()

    def update(self):
        # Defer updates if editing
        if self.editor:
            self.pending_update = True
        else:
            self.on_update()

    def on_update(self):
        pass

    def get_leaves(self, root):
        child_count = root.childCount()
        if child_count == 0:
            yield root
        for i in range(child_count):
            item = root.child(i)
            for x in self.get_leaves(item):
                yield x

    def filter(self, p, columns):
        p = unicode(p).lower()
        for item in self.get_leaves(self.invisibleRootItem()):
            item.setHidden(all([unicode(item.text(column)).lower().find(p) == -1
                                for column in columns]))


class ButtonsWidget(QWidget):

    def __init__(self):
        super(QWidget, self).__init__()
        self.buttons = []

    def resizeButtons(self):
        frameWidth = self.style().pixelMetric(QStyle.PM_DefaultFrameWidth)
        x = self.rect().right() - frameWidth
        y = self.rect().bottom() - frameWidth
        for button in self.buttons:
            sz = button.sizeHint()
            x -= sz.width()
            button.move(x, y - sz.height())

    def addButton(self, icon_name, on_click, tooltip):
        button = QToolButton(self)
        button.setIcon(QIcon(icon_name))
        button.setStyleSheet("QToolButton { border: none; hover {border: 1px} pressed {border: 1px} padding: 0px; }")
        button.setVisible(True)
        button.setToolTip(tooltip)
        button.clicked.connect(on_click)
        self.buttons.append(button)
        return button

    def addCopyButton(self, app):
        self.app = app
        f = lambda: self.app.clipboard().setText(str(self.text()))
        self.addButton(":icons/copy.png", f, _("Copy to Clipboard"))

class ButtonsLineEdit(QLineEdit, ButtonsWidget):
    def __init__(self, text=None):
        QLineEdit.__init__(self, text)
        self.buttons = []

    def resizeEvent(self, e):
        o = QLineEdit.resizeEvent(self, e)
        self.resizeButtons()
        return o

class ButtonsTextEdit(QPlainTextEdit, ButtonsWidget):
    def __init__(self, text=None):
        QPlainTextEdit.__init__(self, text)
        self.setText = self.setPlainText
        self.text = self.toPlainText
        self.buttons = []

    def resizeEvent(self, e):
        o = QPlainTextEdit.resizeEvent(self, e)
        self.resizeButtons()
        return o


if __name__ == "__main__":
    app = QApplication([])
    t = WaitingDialog(None, 'testing ...', lambda: [time.sleep(1)], lambda x: QMessageBox.information(None, 'done', "done", _('OK')))
    t.start()
    app.exec_()
