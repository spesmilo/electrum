import os.path
import time
import sys
import platform
import queue
import threading
from collections import namedtuple
from functools import partial, wraps

from electroncash.i18n import _
from electroncash.address import Address
from electroncash.util import print_error, PrintError, Weak
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

if platform.system() == 'Windows':
    MONOSPACE_FONT = 'Lucida Console'
elif platform.system() == 'Darwin':
    MONOSPACE_FONT = 'Monaco'
else:
    MONOSPACE_FONT = 'monospace'


dialogs = []

from electroncash.paymentrequest import PR_UNPAID, PR_PAID, PR_EXPIRED

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
        self.thread = None
        self.on_success = on_success
        self.on_error = on_error
        self.clicked.connect(self.run_task)

    def run_task(self):
        self.setEnabled(False)
        self.thread = TaskThread(self)
        self.thread.add(self.task, self.on_success, self.done, self.on_error)

    def done(self):
        self.thread.stop()
        self.thread.wait()
        self.setEnabled(True)
        self.thread = None


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

class MessageBoxMixin:
    def top_level_window_recurse(self, window=None):
        window = window or self
        classes = (WindowModalDialog, QMessageBox)
        for n, child in enumerate(window.children()):
            # Test for visibility as old closed dialogs may not be GC-ed
            if isinstance(child, classes) and child.isVisible():
                return self.top_level_window_recurse(child)
        return window

    def top_level_window(self):
        return self.top_level_window_recurse()

    def question(self, msg, parent=None, title=None, icon=None):
        Yes, No = QMessageBox.Yes, QMessageBox.No
        return self.msg_box(icon or QMessageBox.Question,
                            parent, title or '',
                            msg, buttons=Yes|No, defaultButton=No) == Yes

    def show_warning(self, msg, parent=None, title=None, **kwargs):
        return self.msg_box(QMessageBox.Warning, parent,
                            title or _('Warning'), msg, **kwargs)

    def show_error(self, msg, parent=None, **kwargs):
        return self.msg_box(QMessageBox.Warning, parent,
                            _('Error'), msg, **kwargs)

    def show_critical(self, msg, parent=None, title=None, **kwargs):
        return self.msg_box(QMessageBox.Critical, parent,
                            title or _('Critical Error'), msg, **kwargs)

    def show_message(self, msg, parent=None, title=None, **kwargs):
        return self.msg_box(QMessageBox.Information, parent,
                            title or _('Information'), msg, **kwargs)

    def msg_box(self, icon, parent, title, text, buttons=QMessageBox.Ok,
                defaultButton=QMessageBox.NoButton, rich_text=False, detail_text=None):
        parent = parent or self.top_level_window()
        d = QMessageBoxMixin(icon, title, str(text), buttons, parent)
        d.setWindowModality(Qt.WindowModal)
        d.setDefaultButton(defaultButton)
        if detail_text and isinstance(detail_text, str):
            d.setDetailedText(detail_text)
        if rich_text:
            d.setTextInteractionFlags(Qt.TextSelectableByMouse|Qt.LinksAccessibleByMouse)
            d.setTextFormat(Qt.RichText)
        else:
            d.setTextInteractionFlags(Qt.TextSelectableByMouse)
            d.setTextFormat(Qt.PlainText)
        ret = d.exec_()
        d.setParent(None) # Force GC sooner rather than later.
        return ret

class QMessageBoxMixin(QMessageBox, MessageBoxMixin):
    ''' This class's sole purpose is so that MessageBoxMixin.msg_box() always
    presents a message box that has the mixin methods.
    See https://github.com/Electron-Cash/Electron-Cash/issues/980. '''
    pass

class WindowModalDialog(QDialog, MessageBoxMixin):
    '''Handy wrapper; window modal dialogs are better for our multi-window
    daemon model as other wallet windows can still be accessed.'''
    def __init__(self, parent, title=None):
        QDialog.__init__(self, parent)
        self.setWindowModality(Qt.WindowModal)
        if title:
            self.setWindowTitle(title)


class WaitingDialog(WindowModalDialog):
    '''Shows a please wait dialog whilst runnning a task.  It is not
    necessary to maintain a reference to this dialog.'''
    def __init__(self, parent, message, task, on_success=None, on_error=None, auto_cleanup=True):
        assert parent
        if isinstance(parent, MessageBoxMixin):
            parent = parent.top_level_window()
        WindowModalDialog.__init__(self, parent, _("Please wait"))
        vbox = QVBoxLayout(self)
        vbox.addWidget(QLabel(message))
        self.accepted.connect(self.on_accepted)
        self.show() # Bug here -- user can hit ESC key and kill the dialog before it's done. TODO: FIX!
        self.thread = TaskThread(self)
        self.thread.add(task, on_success, self.accept, on_error)
        self.auto_cleanup = auto_cleanup

    def wait(self):
        self.thread.wait()

    def on_accepted(self):
        self.thread.stop()
        if self.auto_cleanup:
            self.wait() # wait for thread to complete so that we can get cleaned up
            self.setParent(None) # this causes GC to happen sooner rather than later. Before this call was added the WaitingDialogs would stick around in memory until the ElectrumWindow was closed and would never get GC'd before then. (as of PyQt5 5.11.3)


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

def text_dialog(parent, title, label, ok_label, default=None, allow_multi=False):
    from .qrtextedit import ScanQRTextEdit
    dialog = WindowModalDialog(parent, title)
    dialog.setMinimumWidth(500)
    l = QVBoxLayout()
    dialog.setLayout(l)
    l.addWidget(QLabel(label))
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

def address_combo(addresses):
    addr_combo = QComboBox()
    addr_combo.addItems(addr.to_ui_string() for addr in addresses)
    addr_combo.setCurrentIndex(0)

    hbox = QHBoxLayout()
    hbox.addWidget(QLabel(_('Address to sweep to:')))
    hbox.addWidget(addr_combo)
    return hbox, addr_combo


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

        # Control which columns are editable
        self.editor = None
        self.pending_update = False
        if editable_columns is None:
            editable_columns = [stretch_column]
        self.editable_columns = editable_columns
        self.setItemDelegate(ElectrumItemDelegate(self))
        self.itemDoubleClicked.connect(self.on_doubleclick)
        self.update_headers(headers)
        self.current_filter = ""

    def update_headers(self, headers):
        self.setColumnCount(len(headers))
        self.setHeaderLabels(headers)
        self.header().setStretchLastSection(False)
        for col in range(len(headers)):
            sm = QHeaderView.Stretch if col == self.stretch_column else QHeaderView.ResizeToContents
            self.header().setSectionResizeMode(col, sm)

    def editItem(self, item, column):
        if item and column in self.editable_columns:
            self.editing_itemcol = (item, column, item.text(column))
            # Calling setFlags causes on_changed events for some reason
            item.setFlags(item.flags() | Qt.ItemIsEditable)
            super().editItem(item, column)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)

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
        self.parent.update_labels()

    def update(self):
        # Defer updates if editing
        if self.editor:
            self.pending_update = True
        else:
            self.setUpdatesEnabled(False)
            scroll_pos_val = self.verticalScrollBar().value() # save previous scroll bar position
            self.on_update()
            def restoreScrollBar():
                self.updateGeometry()
                self.verticalScrollBar().setValue(scroll_pos_val) # restore scroll bar to previous
                self.setUpdatesEnabled(True)
            QTimer.singleShot(1.0, restoreScrollBar) # need to do this from a timer some time later due to Qt quirks
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

    def on_done(self, result, cb_done, cb):
        # This runs in the parent's thread.
        if cb_done:
            cb_done()
        if cb:
            cb(result)

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
    RED = ColorSchemeItem("#7c1111", "#f18c8c")
    BLUE = ColorSchemeItem("#123b7c", "#8cb3f2")
    DEFAULT = ColorSchemeItem("black", "white")

    @staticmethod
    def has_dark_background(widget):
        brightness = sum(widget.palette().color(QPalette.Background).getRgb()[0:3])
        return brightness < (255*3/2)

    @staticmethod
    def update_from_widget(widget):
        if ColorScheme.has_dark_background(widget):
            ColorScheme.dark_scheme = True


class SortableTreeWidgetItem(QTreeWidgetItem):
    DataRole = Qt.UserRole + 1

    def __lt__(self, other):
        column = self.treeWidget().sortColumn()
        self_data = self.data(column, self.DataRole)
        other_data = other.data(column, self.DataRole)
        if None not in (self_data, other_data):
            # We have set custom data to sort by
            return self_data < other_data
        try:
            # Is the value something numeric?
            self_text = self.text(column).replace(',', '')
            other_text = other.text(column).replace(',', '')
            return float(self_text) < float(other_text)
        except ValueError:
            # If not, we will just do string comparison
            return self.text(column) < other.text(column)

class OPReturnError(Exception):
    """ thrown when the OP_RETURN for a tx not of the right format """

class OPReturnTooLarge(OPReturnError):
    """ thrown when the OP_RETURN for a tx is >220 bytes """

class RateLimiter(PrintError):
    ''' Manages the state of a @rate_limited decorated function, collating
    multiple invocations. This class is not intented to be used directly. Instead,
    use the @rate_limited decorator (for instance methods).

    This state instance gets inserted into the instance attributes of the target
    object wherever a @rate_limited decorator appears.

    The inserted attribute is named "__FUNCNAME__RateLimiter". '''
    # some defaults
    last_ts = 0.0
    timer = None
    saved_args = (tuple(),dict())
    ctr = 0

    def __init__(self, rate, obj, func):
        self.n = func.__name__
        self.qn = func.__qualname__
        self.rate = rate
        self.obj = Weak.ref(obj) # keep a weak reference to the object to prevent cycles
        self.func = func
        #self.print_error("*** Created: func=",func,"obj=",obj,"rate=",rate)

    def diagnostic_name(self):
        return "{}:{}".format("rate_limited",self.qn)

    def kill_timer(self):
        if self.timer:
            #self.print_error("deleting timer")
            self.timer.stop()
            self.timer.deleteLater()
            self.timer = None

    @classmethod
    def attr_name(cls, func): return "__{}__{}".format(func.__name__, cls.__name__)

    @classmethod
    def invoke(cls, rate, func, args, kwargs):
        ''' Calls _invoke() on an existing RateLimiter object (or creates a new
        one for the given function on first run per target object instance). '''
        assert args and isinstance(args[0], object), "@rate_limited decorator may only be used with object instance methods"
        assert threading.current_thread() is threading.main_thread(), "@rate_limited decorator may only be used with functions called in the main thread"
        obj = args[0]
        a_name = cls.attr_name(func)
        #print_error("*** a_name =",a_name,"obj =",obj)
        rl = getattr(obj, a_name, None) # we hide the RateLimiter state object in an attribute (name based on the wrapped function name) in the target object
        if rl is None:
            # must be the first invocation, create a new RateLimiter state instance.
            rl = cls(rate, obj, func)
            setattr(obj, a_name, rl)
        return rl._invoke(args, kwargs)

    def _invoke(self, args, kwargs):
        self._push_args(args, kwargs)  # since we're collating, save latest invocation's args unconditionally. any future invocation will use the latest saved args.
        self.ctr += 1 # increment call counter
        #self.print_error("args_saved",args,"kwarg_saved",kwargs)
        if not self.timer: # check if there's a pending invocation already
            now = time.time()
            diff = float(self.rate) - (now - self.last_ts)
            if diff <= 0:
                # Time since last invocation was greater than self.rate, so call the function directly now.
                #self.print_error("calling directly")
                return self._doIt()
            else:
                # Time since last invocation was less than self.rate, so defer to the future with a timer.
                self.timer = QTimer(self.obj() if isinstance(self.obj(), QObject) else None)
                self.timer.timeout.connect(self._doIt)
                #self.timer.destroyed.connect(lambda x=None,qn=self.qn: print(qn,"Timer deallocated"))
                self.timer.setSingleShot(True)
                self.timer.start(diff*1e3)
                #self.print_error("deferring")
        else:
            # We had a timer active, which means as future call will occur. So return early and let that call happenin the future.
            # Note that a side-effect of this aborted invocation was to update self.saved_args.
            pass
            #self.print_error("ignoring (already scheduled)")

    def _pop_args(self):
        args, kwargs = self.saved_args # grab the latest collated invocation's args. this attribute is always defined.
        self.saved_args = (tuple(),dict()) # clear saved args immediately
        return args, kwargs

    def _push_args(self, args, kwargs):
        self.saved_args = (args, kwargs)

    def _doIt(self):
        #self.print_error("called!")
        t0 = time.time()
        args, kwargs = self._pop_args()
        #self.print_error("args_actually_used",args,"kwarg_actually_used",kwargs)
        ctr0 = self.ctr # read back current call counter to compare later for reentrancy detection
        retval = self.func(*args, **kwargs) # and.. call the function. use latest invocation's args
        was_reentrant = self.ctr != ctr0 # if ctr is not the same, func() led to a call this function!
        del args, kwargs # deref args right away (allow them to get gc'd)
        tf = time.time()
        time_taken = tf-t0
        if time_taken > float(self.rate):
            self.print_error("method took too long: {} > {}. Fudging timestamps to compensate.".format(time_taken, self.rate))
            self.last_ts = tf # Hmm. This function takes longer than its rate to complete. so mark its last run time as 'now'. This breaks the rate but at least prevents this function from starving the CPU (benforces a delay).
        else:
            self.last_ts = t0 # Function takes less than rate to complete, so mark its t0 as when we entered to keep the rate constant.

        if self.timer: # timer is not None if and only if we were a delayed (collated) invocation.
            if was_reentrant:
                # we got a reentrant call to this function as a result of calling func() above! re-schedule the timer.
                self.print_error("*** detected a re-entrant call, re-starting timer")
                time_left = float(self.rate) - (tf - self.last_ts)
                self.timer.start(time_left*1e3)
            else:
                # We did not get a reentrant call, so kill the timer so subsequent calls can schedule the timer and/or call func() immediately.
                self.kill_timer()
        elif was_reentrant:
            self.print_error("*** detected a re-entrant call")

        return retval


class RateLimiterClassLvl(RateLimiter):
    ''' This RateLimiter object is used if classlevel=True is specified to the
    @rate_limited decorator.  It inserts the __RateLimiterClassLvl state object
    on the class level and collates calls for all instances to not exceed rate.

    Each instance is guaranteed to receive at least 1 call and to have multiple
    calls updated with the latest args for the final call. So for instance:

    a.foo(1)
    a.foo(2)
    b.foo(10)
    b.foo(3)

    Would collate to a single 'class-level' call using 'rate':

    a.foo(2) # latest arg taken, collapsed to 1 call
    b.foo(3) # latest arg taken, collapsed to 1 call

    '''

    @classmethod
    def invoke(cls, rate, func, args, kwargs):
        assert args and not isinstance(args[0], type), "@rate_limited decorator may not be used with static or class methods"
        obj = args[0]
        objcls = obj.__class__
        args = list(args)
        args.insert(0, objcls) # prepend obj class to trick super.invoke() into making this state object be class-level.
        return super(RateLimiterClassLvl, cls).invoke(rate, func, args, kwargs)

    def _push_args(self, args, kwargs):
        objcls, obj = args[0:2]
        args = args[2:]
        self.saved_args[obj] = (args, kwargs)

    def _pop_args(self):
        weak_dict = self.saved_args
        self.saved_args = Weak.KeyDictionary()
        return (weak_dict,),dict()

    def _call_func_for_all(self, weak_dict):
        for ref in weak_dict.keyrefs():
            obj = ref()
            if obj:
                args,kwargs = weak_dict[obj]
                #self.print_error("calling for",obj.diagnostic_name() if hasattr(obj, "diagnostic_name") else obj,"timer=",bool(self.timer))
                self.func_target(obj, *args, **kwargs)

    def __init__(self,rate, obj, func):
        # note: obj here is really the __class__ of the obj because we prepended the class in our custom invoke() above.
        super().__init__(rate, obj, func)
        self.func_target = func
        self.func = self._call_func_for_all
        self.saved_args = Weak.KeyDictionary() # we don't use a simple arg tuple, but instead an instance -> args,kwargs dictionary to store collated calls, per instance collated


def rate_limited(rate, classlevel=False):
    """ A Function decorator for rate-limiting GUI event callbacks. Argument
        rate in seconds is the minimum allowed time between subsequent calls of
        this instance of the function. Calls that arrive more frequently than
        rate seconds will be collated into a single call that is deferred onto
        a QTimer. It is preferable to use this decorator on QObject subclass
        instance methods. This decorator is particularly useful in limiting
        frequent calls to GUI update functions.
        (See on_fx_quotes and on_fx_history in main_window.py for an example). """
    def wrapper0(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if classlevel:
                return RateLimiterClassLvl.invoke(rate, func, args, kwargs)
            return RateLimiter.invoke(rate, func, args, kwargs)
        return wrapper
    return wrapper0


if __name__ == "__main__":
    app = QApplication([])
    t = WaitingDialog(None, 'testing ...', lambda: [time.sleep(1)], lambda x: QMessageBox.information(None, 'done', "done"))
    t.start()
    app.exec_()
