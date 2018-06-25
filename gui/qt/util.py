import os.path
import time
import sys
import platform
import queue
from collections import namedtuple
from functools import partial

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

from electrum_ltc.i18n import _
from electrum_ltc.util import FileImportFailed, FileExportFailed
from electrum_ltc.paymentrequest import PR_UNPAID, PR_PAID, PR_EXPIRED


if platform.system() == 'Windows':
    MONOSPACE_FONT = 'Lucida Console'
elif platform.system() == 'Darwin':
    MONOSPACE_FONT = 'Monaco'
else:
    MONOSPACE_FONT = 'monospace'


dialogs = []

pr_icons = {
    PR_UNPAID:":icons/unpaid.png",
    PR_PAID:":icons/confirmed.png",
    PR_EXPIRED:":icons/expired.png"
}

pr_tooltips = {
    PR_UNPAID:_('Pending'),
    PR_PAID:_('Paid'),
    PR_EXPIRED:_('Expired')
}

expiration_values = [
    (_('1 hour'), 60*60),
    (_('1 day'), 24*60*60),
    (_('1 week'), 7*24*60*60),
    (_('Never'), None)
]


class Timer(QThread):
    stopped = False
    timer_signal = pyqtSignal()

    def run(self):
        while not self.stopped:
            self.timer_signal.emit()
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
            self.func()


class ThreadedButton(QPushButton):
    def __init__(self, text, task, on_success=None, on_error=None):
        QPushButton.__init__(self, text)
        self.task = task
        self.on_success = on_success
        self.on_error = on_error
        self.clicked.connect(self.run_task)

    def run_task(self):
        self.setEnabled(False)
        self.thread = TaskThread(self)
        self.thread.add(self.task, self.on_success, self.done, self.on_error)

    def done(self):
        self.setEnabled(True)
        self.thread.stop()


class WWLabel(QLabel):
    def __init__ (self, text="", parent=None):
        QLabel.__init__(self, text, parent)
        self.setWordWrap(True)


class HelpLabel(QLabel):

    def __init__(self, text, help_text):
        QLabel.__init__(self, text)
        self.help_text = help_text
        self.app = QCoreApplication.instance()
        self.font = QFont()

    def mouseReleaseEvent(self, x):
        QMessageBox.information(self, 'Help', self.help_text)

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
        QMessageBox.information(self, 'Help', self.help_text)


class InfoButton(QPushButton):
    def __init__(self, text):
        QPushButton.__init__(self, 'Info')
        self.help_text = text
        self.setFocusPolicy(Qt.NoFocus)
        self.setFixedWidth(60)
        self.clicked.connect(self.onclick)

    def onclick(self):
        QMessageBox.information(self, 'Info', self.help_text)


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

class MessageBoxMixin(object):
    def top_level_window_recurse(self, window=None, test_func=None):
        window = window or self
        classes = (WindowModalDialog, QMessageBox)
        if test_func is None:
            test_func = lambda x: True
        for n, child in enumerate(window.children()):
            # Test for visibility as old closed dialogs may not be GC-ed.
            # Only accept children that confirm to test_func.
            if isinstance(child, classes) and child.isVisible() \
                    and test_func(child):
                return self.top_level_window_recurse(child, test_func=test_func)
        return window

    def top_level_window(self, test_func=None):
        return self.top_level_window_recurse(test_func)

    def question(self, msg, parent=None, title=None, icon=None):
        Yes, No = QMessageBox.Yes, QMessageBox.No
        return self.msg_box(icon or QMessageBox.Question,
                            parent, title or '',
                            msg, buttons=Yes|No, defaultButton=No) == Yes

    def show_warning(self, msg, parent=None, title=None):
        return self.msg_box(QMessageBox.Warning, parent,
                            title or _('Warning'), msg)

    def show_error(self, msg, parent=None):
        return self.msg_box(QMessageBox.Warning, parent,
                            _('Error'), msg)

    def show_critical(self, msg, parent=None, title=None):
        return self.msg_box(QMessageBox.Critical, parent,
                            title or _('Critical Error'), msg)

    def show_message(self, msg, parent=None, title=None):
        return self.msg_box(QMessageBox.Information, parent,
                            title or _('Information'), msg)

    def msg_box(self, icon, parent, title, text, buttons=QMessageBox.Ok,
                defaultButton=QMessageBox.NoButton):
        parent = parent or self.top_level_window()
        if type(icon) is QPixmap:
            d = QMessageBox(QMessageBox.Information, title, str(text), buttons, parent)
            d.setIconPixmap(icon)
        else:
            d = QMessageBox(icon, title, str(text), buttons, parent)
        d.setWindowModality(Qt.WindowModal)
        d.setDefaultButton(defaultButton)
        d.setTextInteractionFlags(Qt.TextSelectableByMouse)
        return d.exec_()

class WindowModalDialog(QDialog, MessageBoxMixin):
    '''Handy wrapper; window modal dialogs are better for our multi-window
    daemon model as other wallet windows can still be accessed.'''
    def __init__(self, parent, title=None):
        QDialog.__init__(self, parent)
        self.setWindowModality(Qt.WindowModal)
        if title:
            self.setWindowTitle(title)


class WaitingDialog(WindowModalDialog):
    '''Shows a please wait dialog whilst running a task.  It is not
    necessary to maintain a reference to this dialog.'''
    def __init__(self, parent, message, task, on_success=None, on_error=None):
        assert parent
        if isinstance(parent, MessageBoxMixin):
            parent = parent.top_level_window()
        WindowModalDialog.__init__(self, parent, _("Please wait"))
        vbox = QVBoxLayout(self)
        vbox.addWidget(QLabel(message))
        self.accepted.connect(self.on_accepted)
        self.show()
        self.thread = TaskThread(self)
        self.thread.finished.connect(self.deleteLater)  # see #3956
        self.thread.add(task, on_success, self.accept, on_error)

    def wait(self):
        self.thread.wait()

    def on_accepted(self):
        self.thread.stop()


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
        return txt.text()

def text_dialog(parent, title, header_layout, ok_label, default=None, allow_multi=False):
    from .qrtextedit import ScanQRTextEdit
    dialog = WindowModalDialog(parent, title)
    dialog.setMinimumWidth(600)
    l = QVBoxLayout()
    dialog.setLayout(l)
    if isinstance(header_layout, str):
        l.addWidget(QLabel(header_layout))
    else:
        l.addLayout(header_layout)
    txt = ScanQRTextEdit(allow_multi=allow_multi)
    if default:
        txt.setText(default)
    l.addWidget(txt)
    l.addLayout(Buttons(CancelButton(dialog), OkButton(dialog, ok_label)))
    if dialog.exec_():
        return txt.toPlainText()

class ChoicesLayout(object):
    def __init__(self, msg, choices, on_clicked=None, checked_index=0):
        vbox = QVBoxLayout()
        if len(msg) > 50:
            vbox.addWidget(WWLabel(msg))
            msg = ""
        gb2 = QGroupBox(msg)
        vbox.addWidget(gb2)

        vbox2 = QVBoxLayout()
        gb2.setLayout(vbox2)

        self.group = group = QButtonGroup()
        for i,c in enumerate(choices):
            button = QRadioButton(gb2)
            button.setText(c)
            vbox2.addWidget(button)
            group.addButton(button)
            group.setId(button, i)
            if i==checked_index:
                button.setChecked(True)

        if on_clicked:
            group.buttonClicked.connect(partial(on_clicked, self))

        self.vbox = vbox

    def layout(self):
        return self.vbox

    def selected_index(self):
        return self.group.checkedId()

def address_field(addresses):
    hbox = QHBoxLayout()
    address_e = QLineEdit()
    if addresses and len(addresses) > 0:
        address_e.setText(addresses[0])
    else:
        addresses = []
    def func():
        try:
            i = addresses.index(str(address_e.text())) + 1
            i = i % len(addresses)
            address_e.setText(addresses[i])
        except ValueError:
            # the user might have changed address_e to an
            # address not in the wallet (or to something that isn't an address)
            if addresses and len(addresses) > 0:
                address_e.setText(addresses[0])
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

    directory = config.get('io_dir', os.path.expanduser('~'))
    path = os.path.join( directory, defaultname )
    filename_e = QLineEdit()
    filename_e.setText(path)

    def func():
        text = filename_e.text()
        _filter = "*.csv" if text.endswith(".csv") else "*.json" if text.endswith(".json") else None
        p, __ = QFileDialog.getSaveFileName(None, select_msg, text, _filter)
        if p:
            filename_e.setText(p)

    button = QPushButton(_('File'))
    button.clicked.connect(func)
    hbox.addWidget(button)
    hbox.addWidget(filename_e)
    vbox.addLayout(hbox)

    def set_csv(v):
        text = filename_e.text()
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
        self.config = self.parent.config
        self.stretch_column = stretch_column
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(create_menu)
        self.setUniformRowHeights(True)
        # extend the syntax for consistency
        self.addChild = self.addTopLevelItem
        self.insertChild = self.insertTopLevelItem

        self.icon_cache = IconCache()

        # Control which columns are editable
        self.editor = None
        self.pending_update = False
        if editable_columns is None:
            editable_columns = {stretch_column}
        else:
            editable_columns = set(editable_columns)
        self.editable_columns = editable_columns
        self.setItemDelegate(ElectrumItemDelegate(self))
        self.itemDoubleClicked.connect(self.on_doubleclick)
        self.update_headers(headers)
        self.current_filter = ""

        self.setRootIsDecorated(False)  # remove left margin
        self.toolbar_shown = False

    def update_headers(self, headers):
        self.setColumnCount(len(headers))
        self.setHeaderLabels(headers)
        self.header().setStretchLastSection(False)
        for col in range(len(headers)):
            sm = QHeaderView.Stretch if col == self.stretch_column else QHeaderView.ResizeToContents
            self.header().setSectionResizeMode(col, sm)

    def editItem(self, item, column):
        if column in self.editable_columns:
            try:
                self.editing_itemcol = (item, column, item.text(column))
                # Calling setFlags causes on_changed events for some reason
                item.setFlags(item.flags() | Qt.ItemIsEditable)
                QTreeWidget.editItem(self, item, column)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            except RuntimeError:
                # (item) wrapped C/C++ object has been deleted
                pass

    def keyPressEvent(self, event):
        if event.key() in [ Qt.Key_F2, Qt.Key_Return ] and self.editor is None:
            self.on_activated(self.currentItem(), self.currentColumn())
        else:
            QTreeWidget.keyPressEvent(self, event)

    def permit_edit(self, item, column):
        return (column in self.editable_columns
                and self.on_permit_edit(item, column))

    def on_permit_edit(self, item, column):
        return True

    def on_doubleclick(self, item, column):
        if self.permit_edit(item, column):
            self.editItem(item, column)

    def on_activated(self, item, column):
        # on 'enter' we show the menu
        pt = self.visualItemRect(item).bottomLeft()
        pt.setX(50)
        self.customContextMenuRequested.emit(pt)

    def createEditor(self, parent, option, index):
        self.editor = QStyledItemDelegate.createEditor(self.itemDelegate(),
                                                       parent, option, index)
        self.editor.editingFinished.connect(self.editing_finished)
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
        key = item.data(0, Qt.UserRole)
        text = item.text(column)
        self.parent.wallet.set_label(key, text)
        self.parent.history_list.update_labels()
        self.parent.update_completions()

    def update(self):
        # Defer updates if editing
        if self.editor:
            self.pending_update = True
        else:
            self.setUpdatesEnabled(False)
            scroll_pos = self.verticalScrollBar().value()
            self.on_update()
            self.setUpdatesEnabled(True)
            # To paint the list before resetting the scroll position
            self.parent.app.processEvents()
            self.verticalScrollBar().setValue(scroll_pos)
        if self.current_filter:
            self.filter(self.current_filter)

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

    def filter(self, p):
        columns = self.__class__.filter_columns
        p = p.lower()
        self.current_filter = p
        for item in self.get_leaves(self.invisibleRootItem()):
            item.setHidden(all([item.text(column).lower().find(p) == -1
                                for column in columns]))

    def create_toolbar(self, config=None):
        hbox = QHBoxLayout()
        buttons = self.get_toolbar_buttons()
        for b in buttons:
            b.setVisible(False)
            hbox.addWidget(b)
        hide_button = QPushButton('x')
        hide_button.setVisible(False)
        hide_button.pressed.connect(lambda: self.show_toolbar(False, config))
        self.toolbar_buttons = buttons + (hide_button,)
        hbox.addStretch()
        hbox.addWidget(hide_button)
        return hbox

    def save_toolbar_state(self, state, config):
        pass  # implemented in subclasses

    def show_toolbar(self, state, config=None):
        if state == self.toolbar_shown:
            return
        self.toolbar_shown = state
        if config:
            self.save_toolbar_state(state, config)
        for b in self.toolbar_buttons:
            b.setVisible(state)
        if not state:
            self.on_hide_toolbar()

    def toggle_toolbar(self, config=None):
        self.show_toolbar(not self.toolbar_shown, config)


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
        self.addButton(":icons/copy.png", self.on_copy, _("Copy to clipboard"))

    def on_copy(self):
        self.app.clipboard().setText(self.text())
        QToolTip.showText(QCursor.pos(), _("Text copied to clipboard"), self)

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


class TaskThread(QThread):
    '''Thread that runs background tasks.  Callbacks are guaranteed
    to happen in the context of its parent.'''

    Task = namedtuple("Task", "task cb_success cb_done cb_error")
    doneSig = pyqtSignal(object, object, object)

    def __init__(self, parent, on_error=None):
        super(TaskThread, self).__init__(parent)
        self.on_error = on_error
        self.tasks = queue.Queue()
        self.doneSig.connect(self.on_done)
        self.start()

    def add(self, task, on_success=None, on_done=None, on_error=None):
        on_error = on_error or self.on_error
        self.tasks.put(TaskThread.Task(task, on_success, on_done, on_error))

    def run(self):
        while True:
            task = self.tasks.get()
            if not task:
                break
            try:
                result = task.task()
                self.doneSig.emit(result, task.cb_done, task.cb_success)
            except BaseException:
                self.doneSig.emit(sys.exc_info(), task.cb_done, task.cb_error)

    def on_done(self, result, cb_done, cb_result):
        # This runs in the parent's thread.
        if cb_done:
            cb_done()
        if cb_result:
            cb_result(result)

    def stop(self):
        self.tasks.put(None)


class ColorSchemeItem:
    def __init__(self, fg_color, bg_color):
        self.colors = (fg_color, bg_color)

    def _get_color(self, background):
        return self.colors[(int(background) + int(ColorScheme.dark_scheme)) % 2]

    def as_stylesheet(self, background=False):
        css_prefix = "background-" if background else ""
        color = self._get_color(background)
        return "QWidget {{ {}color:{}; }}".format(css_prefix, color)

    def as_color(self, background=False):
        color = self._get_color(background)
        return QColor(color)


class ColorScheme:
    dark_scheme = False

    GREEN = ColorSchemeItem("#117c11", "#8af296")
    YELLOW = ColorSchemeItem("#897b2a", "#ffff00")
    RED = ColorSchemeItem("#7c1111", "#f18c8c")
    BLUE = ColorSchemeItem("#123b7c", "#8cb3f2")
    DEFAULT = ColorSchemeItem("black", "white")

    @staticmethod
    def has_dark_background(widget):
        brightness = sum(widget.palette().color(QPalette.Background).getRgb()[0:3])
        return brightness < (255*3/2)

    @staticmethod
    def update_from_widget(widget, force_dark=False):
        if force_dark or ColorScheme.has_dark_background(widget):
            ColorScheme.dark_scheme = True


class AcceptFileDragDrop:
    def __init__(self, file_type=""):
        assert isinstance(self, QWidget)
        self.setAcceptDrops(True)
        self.file_type = file_type

    def validateEvent(self, event):
        if not event.mimeData().hasUrls():
            event.ignore()
            return False
        for url in event.mimeData().urls():
            if not url.toLocalFile().endswith(self.file_type):
                event.ignore()
                return False
        event.accept()
        return True

    def dragEnterEvent(self, event):
        self.validateEvent(event)

    def dragMoveEvent(self, event):
        if self.validateEvent(event):
            event.setDropAction(Qt.CopyAction)

    def dropEvent(self, event):
        if self.validateEvent(event):
            for url in event.mimeData().urls():
                self.onFileAdded(url.toLocalFile())

    def onFileAdded(self, fn):
        raise NotImplementedError()


def import_meta_gui(electrum_window, title, importer, on_success):
    filter_ = "JSON (*.json);;All files (*)"
    filename = electrum_window.getOpenFileName(_("Open {} file").format(title), filter_)
    if not filename:
        return
    try:
        importer(filename)
    except FileImportFailed as e:
        electrum_window.show_critical(str(e))
    else:
        electrum_window.show_message(_("Your {} were successfully imported").format(title))
        on_success()


def export_meta_gui(electrum_window, title, exporter):
    filter_ = "JSON (*.json);;All files (*)"
    filename = electrum_window.getSaveFileName(_("Select file to save your {}").format(title),
                                               'electrum-ltc_{}.json'.format(title), filter_)
    if not filename:
        return
    try:
        exporter(filename)
    except FileExportFailed as e:
        electrum_window.show_critical(str(e))
    else:
        electrum_window.show_message(_("Your {0} were exported to '{1}'")
                                     .format(title, str(filename)))


def get_parent_main_window(widget):
    """Returns a reference to the ElectrumWindow this widget belongs to."""
    from .main_window import ElectrumWindow
    for _ in range(100):
        if widget is None:
            return None
        if not isinstance(widget, ElectrumWindow):
            widget = widget.parentWidget()
        else:
            return widget
    return None

class SortableTreeWidgetItem(QTreeWidgetItem):
    DataRole = Qt.UserRole + 1

    def __lt__(self, other):
        column = self.treeWidget().sortColumn()
        if None not in [x.data(column, self.DataRole) for x in [self, other]]:
            # We have set custom data to sort by
            return self.data(column, self.DataRole) < other.data(column, self.DataRole)
        try:
            # Is the value something numeric?
            return float(self.text(column)) < float(other.text(column))
        except ValueError:
            # If not, we will just do string comparison
            return self.text(column) < other.text(column)


class IconCache:

    def __init__(self):
        self.__cache = {}

    def get(self, file_name):
        if file_name not in self.__cache:
            self.__cache[file_name] = QIcon(file_name)
        return self.__cache[file_name]


if __name__ == "__main__":
    app = QApplication([])
    t = WaitingDialog(None, 'testing ...', lambda: [time.sleep(1)], lambda x: QMessageBox.information(None, 'done', "done"))
    t.start()
    app.exec_()
