import os.path
import time
import sys
import platform
import queue
import threading
import os
import webbrowser
from collections import namedtuple
from functools import partial, wraps

from electroncash.address import Address
from electroncash.util import print_error, PrintError, Weak, finalization_print_error
from electroncash.wallet import Abstract_Wallet
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

if platform.system() == 'Windows':
    MONOSPACE_FONT = 'Consolas'
elif platform.system() == 'Darwin':
    MONOSPACE_FONT = 'Monaco'
else:
    MONOSPACE_FONT = 'monospace'


dialogs = []

from electroncash.paymentrequest import PR_UNPAID, PR_PAID, PR_EXPIRED

pr_icons = {
    PR_UNPAID:":icons/unpaid.svg",
    PR_PAID:":icons/confirmed.svg",
    PR_EXPIRED:":icons/expired.svg"
}

def _(message): return message

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

del _
from electroncash.i18n import _



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
        self.setTextInteractionFlags(self.textInteractionFlags() | Qt.TextSelectableByMouse)

# --- Help widgets
class HelpMixin:
    def __init__(self, help_text, *, custom_parent=None):
        assert isinstance(self, QWidget), "HelpMixin must be a QWidget instance!"
        self.help_text = help_text
        self.custom_parent = custom_parent
        if isinstance(self, QLabel):
            self.setTextInteractionFlags(
                (self.textInteractionFlags() | Qt.TextSelectableByMouse)
                & ~Qt.TextSelectableByKeyboard)

    def show_help(self):
        QMessageBox.information(self.custom_parent or self, _('Help'), self.help_text)

class HelpLabel(HelpMixin, QLabel):
    def __init__(self, text, help_text, *, custom_parent=None):
        QLabel.__init__(self, text)
        HelpMixin.__init__(self, help_text, custom_parent=custom_parent)
        self.setCursor(QCursor(Qt.PointingHandCursor))
        self.font = self.font()

    def mouseReleaseEvent(self, x):
        self.show_help()

    def enterEvent(self, event):
        self.font.setUnderline(True)
        self.setFont(self.font)
        return QLabel.enterEvent(self, event)

    def leaveEvent(self, event):
        self.font.setUnderline(False)
        self.setFont(self.font)
        return QLabel.leaveEvent(self, event)

class HelpButton(HelpMixin, QPushButton):
    def __init__(self, text, *, button_text='?', fixed_size=True, icon=None,
                 tool_tip=None, custom_parent=None):
        QPushButton.__init__(self, button_text or '')
        HelpMixin.__init__(self, text, custom_parent=custom_parent)
        self.setToolTip(tool_tip or _("Show help"))
        self.setCursor(QCursor(Qt.PointingHandCursor))
        self.setFocusPolicy(Qt.NoFocus)
        if fixed_size:
            self.setFixedWidth(20)
        if icon:
            self.setIcon(icon)
        self.clicked.connect(self.show_help)
        # The below is for older plugins that may have relied on the existence
        # of this method.  The older version of this class provided this method.
        # Delete this line some day.
        self.onclick = self.show_help

# --- /Help widgets


class Buttons(QHBoxLayout):
    def __init__(self, *buttons):
        QHBoxLayout.__init__(self)
        self.addStretch(1)
        for b in buttons:
            self.addWidget(b)

class CloseButton(QPushButton):
    def __init__(self, dialog):
        QPushButton.__init__(self, _("C&lose"))
        self.clicked.connect(dialog.close)
        self.setDefault(True)

class CopyButton(QPushButton):
    def __init__(self, text_getter, app=None, callback=None):
        QPushButton.__init__(self, _("&Copy"))
        if not app:
            app = QApplication.instance()
        self.clicked.connect(lambda: app.clipboard().setText(text_getter()))
        if callback:
            self.clicked.connect(callback)

class CopyCloseButton(QPushButton):
    def __init__(self, text_getter, app, dialog):
        QPushButton.__init__(self, _("&Copy and Close"))
        self.clicked.connect(lambda: app.clipboard().setText(text_getter()))
        self.clicked.connect(dialog.close)
        self.setDefault(True)

class OkButton(QPushButton):
    def __init__(self, dialog, label=None):
        QPushButton.__init__(self, label or _("&OK"))
        self.clicked.connect(dialog.accept)
        self.setDefault(True)

class CancelButton(QPushButton):
    def __init__(self, dialog, label=None):
        QPushButton.__init__(self, label or _("C&ancel"))
        self.clicked.connect(dialog.reject)

class MessageBoxMixin:
    def top_level_window_recurse(self, window=None):
        window = window or self
        for n, child in enumerate(window.children()):
            if (isinstance(child, QWidget) and child.isWindow()
                    and child.windowModality() != Qt.NonModal
                    # Test for visibility as old closed dialogs may not be GC-ed
                    and child.isVisible()):
                return self.top_level_window_recurse(child)
        return window

    def top_level_window(self):
        return self.top_level_window_recurse()

    def question(self, msg, parent=None, title=None, icon=None, defaultButton=QMessageBox.No, **kwargs):
        Yes, No = QMessageBox.Yes, QMessageBox.No
        retval = self.msg_box(icon or QMessageBox.Question,
                              parent, title or '',
                              msg, buttons=Yes|No, defaultButton=defaultButton, **kwargs)
        if isinstance(retval, (list, tuple)):
            # do some mogrification for new api
            x, *etc = retval
            # old-style API compat. result button is transformed to bool
            x = (x == Yes)
            retval = (x, *etc)
        else:
            # old-style api -- simple result returned
            retval = retval == Yes
        return retval

    def show_warning(self, msg, parent=None, title=None, **kwargs):
        return self.msg_box(QMessageBox.Warning, parent,
                            title or _('Warning'), msg, **kwargs)

    def show_error(self, msg, parent=None, title=None, **kwargs):
        return self.msg_box(QMessageBox.Warning, parent,
                            title or _('Error'), msg, **kwargs)

    def show_critical(self, msg, parent=None, title=None, **kwargs):
        return self.msg_box(QMessageBox.Critical, parent,
                            title or _('Critical Error'), msg, **kwargs)

    def show_message(self, msg, parent=None, title=None, **kwargs):
        return self.msg_box(QMessageBox.Information, parent,
                            title or _('Information'), msg, **kwargs)

    def msg_box(self, icon, parent, title, text,
                buttons=QMessageBox.Ok,  # Also accepts a list/tuple of str's (for custom buttons)
                defaultButton=QMessageBox.NoButton,  # IFF buttons is a list, use a string appearing in the list to specify this
                rich_text=False, detail_text=None, informative_text=None,
                checkbox_text=None, checkbox_ischecked=False,  # If checkbox_text is set, will add a checkbox, and return value becomes a tuple (result(), isChecked())
                escapeButton=QMessageBox.NoButton,  # IFF buttons is a list, use a string appearing in the list to specify this
                app_modal=False  # IFF true, set the popup window to be application modal
                ):
        ''' Note about 'new' msg_box API (this applies to all of the above functions that call into this as well):
            - `icon' may not be either a standard QMessageBox.Icon or a QPixmap for a custom icon.
            - `buttons' may be a list of translated button texts to use, or the old-style QMessageBox.StandardButtons bitfields
            - If `buttons' is a list, the result returned will be an index (int) into this list, signifying which button was clicked.
            - If `buttons' is a list of button texts, then defaultButton= and escapeButton= must also be the text of the button you want to give the designated property to
            - If the `checkbox_text' arg is set, the return value will be a tuple of: ( result(), checkbox.isChecked() )
              (otherwise it's just simple value: result(), if no checkbox_text is specified)
        '''
        parent = parent or self.top_level_window()
        d = QMessageBoxMixin(parent)
        d.setWindowModality(Qt.ApplicationModal if app_modal else Qt.WindowModal)
        d.setWindowTitle(title)
        if isinstance(buttons, (list, tuple)):
            # new! We support a button list, which specifies button text
            # defaultButton must match which button to be default
            # Return value will be the index of the button push in this list!
            for b in buttons:
                assert isinstance(b, (str, QAbstractButton)), "MessageBoxMixin msg_box API usage error: expected a list of str's or QAbstractButtons!"
                role = QMessageBox.AcceptRole if defaultButton == b else QMessageBox.RejectRole
                but = d.addButton(b, role)
                if b == defaultButton:
                    d.setDefaultButton(but)
                if b == escapeButton:
                    d.setEscapeButton(but)
        else:
            # Was the plain-old Qt.StandardButtons usage
            d.setStandardButtons(buttons)
            d.setDefaultButton(defaultButton)
            d.setEscapeButton(escapeButton)
        if isinstance(icon, QPixmap):
            # New! Icon can be a pixmap!
            d.setIconPixmap(icon)
        else:
            d.setIcon(icon)
        if detail_text and isinstance(detail_text, str):
            d.setDetailedText(detail_text)
        if informative_text and isinstance(informative_text, str):
            d.setInformativeText(informative_text)
        if rich_text:
            d.setTextInteractionFlags(d.textInteractionFlags()|Qt.TextSelectableByMouse|Qt.LinksAccessibleByMouse)
            d.setTextFormat(Qt.RichText)
        else:
            d.setTextInteractionFlags(Qt.TextSelectableByMouse)
            d.setTextFormat(Qt.PlainText)
        d.setText(str(text))
        if checkbox_text and isinstance(checkbox_text, str):
            chk = QCheckBox(checkbox_text)
            d.setCheckBox(chk)
            chk.setChecked(bool(checkbox_ischecked))
            d.exec_()
            ret = d.result(), chk.isChecked() # new API returns a tuple if a checkbox is specified
        else:
            d.exec_()
            ret = d.result() # old/no checkbox api
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

class AppModalDialog(MessageBoxMixin, QDialog):
    ''' Convenience class -- like the WindowModalDialog but is app-modal.
    Has all the MessageBoxMixin convenience methods.  Is always top-level and
    parentless.'''
    def __init__(self, parent=None, title=None, windowFlags=None):
        QDialog.__init__(self, parent=parent)
        self.setWindowModality(Qt.ApplicationModal)
        if title:
            self.setWindowTitle(title)
        if windowFlags is not None:
            self.setWindowFlags(windowFlags)


class WaitingDialog(WindowModalDialog):
    '''Shows a please wait dialog whilst runnning a task.  It is not
    necessary to maintain a reference to this dialog.

    Note if disable_escape_key is not set, user can hit cancel to prematurely
    close the dialog. Sometimes this is desirable, and sometimes it isn't, hence
    why the option is offered.'''
    def __init__(self, parent, message, task, on_success=None, on_error=None, auto_cleanup=True,
                 *, auto_show=True, auto_exec=False, title=None, disable_escape_key=False):
        assert parent
        if isinstance(parent, MessageBoxMixin):
            parent = parent.top_level_window()
        WindowModalDialog.__init__(self, parent, title or _("Please wait"))
        self.auto_cleanup = auto_cleanup
        self.disable_escape_key = disable_escape_key
        self._vbox = vbox = QVBoxLayout(self)
        self._label = label = QLabel(message)
        vbox.addWidget(label)
        self.accepted.connect(self.on_accepted)
        self.rejected.connect(self.on_rejected)
        if auto_show and not auto_exec:
            self.open()
        self.thread = TaskThread(self)
        self.thread.add(task, on_success, self.accept, on_error)
        if auto_exec:
            self.exec_()
        finalization_print_error(self)  # track object lifecycle

    def wait(self):
        self.thread.wait()

    def on_accepted(self):
        self.thread.stop()
        if self.auto_cleanup:
            self.wait() # wait for thread to complete so that we can get cleaned up
            self.setParent(None) # this causes GC to happen sooner rather than later. Before this call was added the WaitingDialogs would stick around in memory until the ElectrumWindow was closed and would never get GC'd before then. (as of PyQt5 5.11.3)

    def on_rejected(self):
        if self.auto_cleanup:
            self.setParent(None)

    def keyPressEvent(self, e):
        ''' The user can hit Cancel to close the dialog before the task is done.
        If self.disable_escape_key, then we suppress this unwanted behavior.
        Note: Do not enable self.disable_escape_key for extremely long
        operations.'''
        if e.matches(QKeySequence.Cancel) and self.disable_escape_key:
            e.ignore()
        else:
            super().keyPressEvent(e)



def line_dialog(parent, title, label, ok_label, default=None,
                *, linkActivated=None, placeholder=None, disallow_empty=False,
                icon=None, line_edit_widget=None):
    dialog = WindowModalDialog(parent, title)
    dialog.setObjectName('WindowModalDialog - ' + title)
    destroyed_print_error(dialog)  # track object lifecycle
    dialog.setMinimumWidth(500)
    l = QVBoxLayout()
    dialog.setLayout(l)
    if isinstance(icon, QIcon):
        hbox = QHBoxLayout()
        hbox.setContentsMargins(0,0,0,0)
        ic_lbl = QLabel()
        ic_lbl.setPixmap(icon.pixmap(50))
        hbox.addWidget(ic_lbl)
        hbox.addItem(QSpacerItem(10, 1))
        t_lbl = QLabel("<font size=+1><b>" + title + "</b></font>")
        hbox.addWidget(t_lbl, 0, Qt.AlignLeft)
        hbox.addStretch(1)
        l.addLayout(hbox)
    lbl = WWLabel(label)
    l.addWidget(lbl)
    if linkActivated:
        lbl.linkActivated.connect(linkActivated)
        lbl.setTextInteractionFlags(lbl.textInteractionFlags()|Qt.LinksAccessibleByMouse)
    txt = line_edit_widget or QLineEdit()
    if default:
        txt.setText(default)
    if placeholder:
        txt.setPlaceholderText(placeholder)
    l.addWidget(txt)
    okbut = OkButton(dialog, ok_label)
    l.addLayout(Buttons(CancelButton(dialog), okbut))
    if disallow_empty:
        def on_text_changed():
            okbut.setEnabled(bool(txt.text()))
        txt.textChanged.connect(on_text_changed)
        on_text_changed() # initially enable/disable it.
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
    b2.setText(_("JSON"))
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

    class SortSpec(namedtuple("SortSpec", "column, qt_sort_order")):
        ''' Used to specify member: default_sort '''

    # Specify this in subclasses to apply a default sort order to the widget
    # If None, nothing is applied (items are presented in the order they are
    # added).
    default_sort : SortSpec = None

    # Specify this in subclasses to enable substring search/filtering (Ctrl+F)
    # (if empty, no search is applied)
    filter_columns = []

    def __init__(self, parent, create_menu, headers, stretch_column=None,
                 editable_columns=None,
                 *, deferred_updates=False, save_sort_settings=False):
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
        self.deferred_updates = deferred_updates
        self.deferred_update_ct, self._forced_update = 0, False
        self._save_sort_settings = save_sort_settings

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

        self._setup_save_sort_mechanism()

    def _setup_save_sort_mechanism(self):
        if (self._save_sort_settings
                and isinstance(getattr(self.parent, 'wallet', None), Abstract_Wallet)):
            storage = self.parent.wallet.storage
            key = f'mytreewidget_default_sort_{type(self).__name__}'
            default = (storage and storage.get(key, None)) or self.default_sort
            if default and isinstance(default, (tuple, list)) and len(default) >= 2 and all(isinstance(i, int) for i in default):
                self.setSortingEnabled(True)
                self.sortByColumn(default[0], default[1])
            if storage:
                # Paranoia; hold a weak reference just in case subclass code
                # does unusual things.
                weakStorage = Weak.ref(storage)
                def save_sort(column, qt_sort_order):
                    storage = weakStorage()
                    if storage:
                        storage.put(key, [column, qt_sort_order])
                self.header().sortIndicatorChanged.connect(save_sort)
        elif self.default_sort:
            self.setSortingEnabled(True)
            self.sortByColumn(self.default_sort[0], self.default_sort[1])


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
            item, col = self.currentItem(), self.currentColumn()
            if item and col > -1:
                self.on_activated(item, col)
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
                self.deferred_update_ct = 0

    def on_edited(self, item, column, prior):
        '''Called only when the text actually changes'''
        key = item.data(0, Qt.UserRole)
        text = item.text(column)
        self.parent.wallet.set_label(key, text)
        self.parent.update_labels()

    def should_defer_update_incr(self):
        ret = (self.deferred_updates and not self.isVisible()
               and not self._forced_update )
        if ret:
            self.deferred_update_ct += 1
        return ret

    def update(self):
        # Defer updates if editing
        if self.editor:
            self.pending_update = True
        else:
            # Deferred update mode won't actually update the GUI if it's
            # not on-screen, and will instead update it the next time it is
            # shown.  This has been found to radically speed up large wallets
            # on initial synch or when new TX's arrive.
            if self.should_defer_update_incr():
                return
            self.setUpdatesEnabled(False)
            scroll_pos_val = self.verticalScrollBar().value() # save previous scroll bar position
            self.on_update()
            self.deferred_update_ct = 0
            weakSelf = Weak.ref(self)
            def restoreScrollBar():
                slf = weakSelf()
                if slf:
                    slf.updateGeometry()
                    slf.verticalScrollBar().setValue(scroll_pos_val) # restore scroll bar to previous
                    slf.setUpdatesEnabled(True)
            QTimer.singleShot(0, restoreScrollBar) # need to do this from a timer some time later due to Qt quirks
        if self.current_filter:
            self.filter(self.current_filter)

    def on_update(self):
        # Reimplemented in subclasses
        pass

    def showEvent(self, e):
        super().showEvent(e)
        if e.isAccepted() and self.deferred_update_ct:
            self._forced_update = True
            self.update()
            self._forced_update = False
            # self.deferred_update_ct will be set right after on_update is called because some subclasses use @rate_limiter on the update() method

    def get_leaves(self, root=None):
        if root is None:
            root = self.invisibleRootItem()
        child_count = root.childCount()
        if child_count == 0:
            if root is not self.invisibleRootItem():
                yield root
            else:
                return
        for i in range(child_count):
            item = root.child(i)
            for x in self.get_leaves(item):
                yield x

    def filter(self, p):
        columns = self.__class__.filter_columns
        if not columns:
            return
        p = p.lower()
        self.current_filter = p
        for item in self.get_leaves(self.invisibleRootItem()):
            item.setHidden(all([item.text(column).lower().find(p) == -1
                                for column in columns]))


class OverlayControlMixin:
    STYLE_SHEET_COMMON = '''
    QPushButton { border-width: 1px; padding: 0px; margin: 0px; }
    '''

    STYLE_SHEET_LIGHT = '''
    QPushButton { border: 1px solid transparent; }
    QPushButton:hover { border: 1px solid #3daee9; }
    '''

    def __init__(self, middle: bool = False):
        assert isinstance(self, QWidget)
        self.middle = middle
        self.overlay_widget = QWidget(self)
        style_sheet = self.STYLE_SHEET_COMMON
        if not ColorScheme.dark_scheme:
            style_sheet = style_sheet + self.STYLE_SHEET_LIGHT
        self.overlay_widget.setStyleSheet(style_sheet)
        self.overlay_layout = QHBoxLayout(self.overlay_widget)
        self.overlay_layout.setContentsMargins(0, 0, 0, 0)
        self.overlay_layout.setSpacing(1)
        self._updateOverlayPos()

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._updateOverlayPos()

    def _updateOverlayPos(self):
        frame_width = self.style().pixelMetric(QStyle.PM_DefaultFrameWidth)
        overlay_size = self.overlay_widget.sizeHint()
        x = self.rect().right() - frame_width - overlay_size.width()
        y = self.rect().bottom() - overlay_size.height()
        middle = self.middle
        if hasattr(self, 'document'):
            # Keep the buttons centered if we have less than 2 lines in the editor
            line_spacing = QFontMetrics(self.document().defaultFont()).lineSpacing()
            if self.rect().height() < (line_spacing * 2):
                middle = True
        y = (y / 2) + frame_width if middle else y - frame_width
        if hasattr(self, 'verticalScrollBar') and self.verticalScrollBar().isVisible():
            scrollbar_width = self.style().pixelMetric(QStyle.PM_ScrollBarExtent)
            x -= scrollbar_width
        self.overlay_widget.move(x, y)

    def addWidget(self, widget: QWidget, index: int = None):
        if index is not None:
            self.overlay_layout.insertWidget(index, widget)
        else:
            self.overlay_layout.addWidget(widget)

    def addButton(self, icon_name: str, on_click, tooltip: str, index : int = None,
                  *, text : str = None) -> QAbstractButton:
        ''' icon_name may be None but then you must define text (which is
        hopefully then some nice Unicode character). Both cannot be None.

        `on_click` is the callable to connect to the button.clicked signal.

        Use `index` to insert it not at the end of the layout by anywhere in the
        layout. If None, it will be appended to the right of the layout. '''
        button = QPushButton(self.overlay_widget)
        button.setToolTip(tooltip)
        button.setCursor(QCursor(Qt.PointingHandCursor))
        if icon_name:
            button.setIcon(QIcon(icon_name))
        elif text:
            button.setText(text)
        if not icon_name and not text:
            raise AssertionError('OverlayControlMixin.addButton: Button must have either icon_name or text defined!')
        button.clicked.connect(on_click)
        self.addWidget(button, index)
        return button

    def addCopyButton(self) -> QAbstractButton:
        return self.addButton(":icons/copy.png", self.on_copy, _("Copy to clipboard"))

    def on_copy(self):
        QApplication.instance().clipboard().setText(self.text())
        QToolTip.showText(QCursor.pos(), _("Text copied to clipboard"), self)

    def keyPressEvent(self, e):
        if not self.hasFocus():
            # Ignore keypress when we're not focused like when the focus is on a button
            e.ignore()
            return
        super().keyPressEvent(e)

    def keyReleaseEvent(self, e):
        if not self.hasFocus():
            e.ignore()
            return
        super().keyReleaseEvent(e)

class ButtonsLineEdit(OverlayControlMixin, QLineEdit):
    def __init__(self, text=None):
        QLineEdit.__init__(self, text)
        OverlayControlMixin.__init__(self, middle=True)

class ButtonsTextEdit(OverlayControlMixin, QPlainTextEdit):
    def __init__(self, text=None):
        QPlainTextEdit.__init__(self, text)
        OverlayControlMixin.__init__(self)
        self.setText = self.setPlainText
        self.text = self.toPlainText

class TaskThread(PrintError, QThread):
    '''Thread that runs background tasks.  Callbacks are guaranteed
    to happen in the context of its parent.'''

    Task = namedtuple("Task", "task cb_success cb_done cb_error")
    doneSig = pyqtSignal(object, object, object)

    def __init__(self, parent, on_error=None, *, name=None):
        QThread.__init__(self, parent)
        if name is not None:
            self.setObjectName(name)
        self.on_error = on_error
        self.tasks = queue.Queue()
        self.doneSig.connect(self.on_done)
        Weak.finalization_print_error(self)  # track task thread lifecycle in debug log
        self.start()

    def add(self, task, on_success=None, on_done=None, on_error=None):
        on_error = on_error or self.on_error
        self.tasks.put(TaskThread.Task(task, on_success, on_done, on_error))

    def diagnostic_name(self):
        name = self.__class__.__name__
        o = self.objectName() or ''
        if o:
            name += '/' + o
        return name

    def run(self):
        self.print_error("started")
        try:
            while True:
                task = self.tasks.get()
                if not task:
                    break
                try:
                    result = task.task()
                    self.doneSig.emit(result, task.cb_done, task.cb_success)
                except:
                    self.doneSig.emit(sys.exc_info(), task.cb_done, task.cb_error)
        finally:
            self.print_error("exiting")

    def on_done(self, result, cb_done, cb):
        # This runs in the parent's thread.
        if cb_done:
            cb_done()
        if cb:
            cb(result)

    def stop(self, *, waitTime = None):
        ''' pass optional time to wait in seconds (float).  If no waitTime
        specified, will not wait. '''
        self.tasks.put(None)
        if waitTime is not None and self.isRunning():
            if not self.wait(int(waitTime * 1e3)):  # secs -> msec
                self.print_error(f"wait timed out after {waitTime} seconds")


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
    SLPGREEN = ColorSchemeItem("#25863f", "#8af296") # darker alternative: ColorSchemeItem("#25863f", "#60bc70")
    YELLOW = ColorSchemeItem("#897b2a", "#ffff00")
    PINK = ColorSchemeItem("#9c4444", "#ffbaba")
    RED = ColorSchemeItem("#7c1111", "#f18c8c")
    BLUE = ColorSchemeItem("#123b7c", "#8cb3f2")
    DEFAULT = ColorSchemeItem("black", "white")
    if sys.platform.startswith("win"):
        GRAY = ColorSchemeItem("#6a6864", "#a0a0a4")  # darkGray, gray
    else:
        GRAY = ColorSchemeItem("#777777", "#a0a0a4")  # darkGray, gray

    @staticmethod
    def has_dark_background(widget):
        brightness = sum(widget.palette().color(QPalette.Background).getRgb()[0:3])
        return brightness < (255*3/2)

    @staticmethod
    def update_from_widget(widget, *, force_dark=False):
        if force_dark or ColorScheme.has_dark_background(widget):
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

    def __init__(self, rate, ts_after, obj, func):
        self.n = func.__name__
        self.qn = func.__qualname__
        self.rate = rate
        self.ts_after = ts_after
        self.obj = Weak.ref(obj) # keep a weak reference to the object to prevent cycles
        self.func = func
        #self.print_error("*** Created: func=",func,"obj=",obj,"rate=",rate)

    def diagnostic_name(self):
        return "{}:{}".format("rate_limited",self.qn)

    def kill_timer(self):
        if self.timer:
            #self.print_error("deleting timer")
            try:
                self.timer.stop()
                self.timer.deleteLater()
            except RuntimeError as e:
                if 'c++ object' in str(e).lower():
                    # This can happen if the attached object which actually owns
                    # QTimer is deleted by Qt before this call path executes.
                    # This call path may be executed from a queued connection in
                    # some circumstances, hence the crazyness (I think).
                    self.print_error("advisory: QTimer was already deleted by Qt, ignoring...")
                else:
                    raise
            finally:
                self.timer = None

    @classmethod
    def attr_name(cls, func): return "__{}__{}".format(func.__name__, cls.__name__)

    @classmethod
    def invoke(cls, rate, ts_after, func, args, kwargs):
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
            rl = cls(rate, ts_after, obj, func)
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
        if self.ts_after:
            self.last_ts = tf
        else:
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
    def invoke(cls, rate, ts_after, func, args, kwargs):
        assert args and not isinstance(args[0], type), "@rate_limited decorator may not be used with static or class methods"
        obj = args[0]
        objcls = obj.__class__
        args = list(args)
        args.insert(0, objcls) # prepend obj class to trick super.invoke() into making this state object be class-level.
        return super(RateLimiterClassLvl, cls).invoke(rate, ts_after, func, args, kwargs)

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

    def __init__(self, rate, ts_after, obj, func):
        # note: obj here is really the __class__ of the obj because we prepended the class in our custom invoke() above.
        super().__init__(rate, ts_after, obj, func)
        self.func_target = func
        self.func = self._call_func_for_all
        self.saved_args = Weak.KeyDictionary() # we don't use a simple arg tuple, but instead an instance -> args,kwargs dictionary to store collated calls, per instance collated


def rate_limited(rate, *, classlevel=False, ts_after=False):
    """ A Function decorator for rate-limiting GUI event callbacks. Argument
        rate in seconds is the minimum allowed time between subsequent calls of
        this instance of the function. Calls that arrive more frequently than
        rate seconds will be collated into a single call that is deferred onto
        a QTimer. It is preferable to use this decorator on QObject subclass
        instance methods. This decorator is particularly useful in limiting
        frequent calls to GUI update functions.

        params:
            rate - calls are collated to not exceed rate (in seconds)
            classlevel - if True, specify that the calls should be collated at
                1 per `rate` secs. for *all* instances of a class, otherwise
                calls will be collated on a per-instance basis.
            ts_after - if True, mark the timestamp of the 'last call' AFTER the
                target method completes.  That is, the collation of calls will
                ensure at least `rate` seconds will always elapse between
                subsequent calls. If False, the timestamp is taken right before
                the collated calls execute (thus ensuring a fixed period for
                collated calls).
                TL;DR: ts_after=True : `rate` defines the time interval you want
                                        from last call's exit to entry into next
                                        call.
                       ts_adter=False: `rate` defines the time between each
                                        call's entry.

        (See on_fx_quotes & on_fx_history in main_window.py for example usages
        of this decorator). """
    def wrapper0(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if classlevel:
                return RateLimiterClassLvl.invoke(rate, ts_after, func, args, kwargs)
            return RateLimiter.invoke(rate, ts_after, func, args, kwargs)
        return wrapper
    return wrapper0

def destroyed_print_error(qobject, msg=None):
    ''' Supply a message to be printed via print_error when obj is
    destroyed (Qt C++ deleted). This is useful for debugging memory leaks. '''
    assert isinstance(qobject, QObject), "destroyed_print_error can only be used on QObject instances!"
    if msg is None:
        # Generate a useful message if none is supplied.
        if isinstance(qobject, PrintError):
            name = qobject.diagnostic_name()
        else:
            name = qobject.objectName() or ""
        if not name:
            if isinstance(qobject, QAction) and qobject.text():
                name = "Action: " + qobject.text()
            elif isinstance(qobject, QMenu) and qobject.title():
                name = "QMenu: " + qobject.title()
            else:
                try:
                    name = (qobject.parent().objectName() or qobject.parent().__class__.__qualname__) + "."
                except:
                    pass  # some of the code in this project overrites .parent or it may not have a parent
                name += qobject.__class__.__qualname__
        msg = "[{}] destroyed".format(name)
    qobject.destroyed.connect(lambda x=None,msg=msg: print_error(msg))

def webopen(url: str):
    if (sys.platform == 'linux' and os.environ.get('APPIMAGE')
            and os.environ.get('LD_LIBRARY_PATH') is not None):
        # When on Linux webbrowser.open can fail in AppImage because it can't find the correct libdbus.
        # We just fork the process and unset LD_LIBRARY_PATH before opening the URL.
        # See https://github.com/spesmilo/electrum/issues/5425
        if os.fork() == 0:
            del os.environ['LD_LIBRARY_PATH']
            webbrowser.open(url)
            os._exit(0)  # Python docs advise doing this after forking to prevent atexit handlers from executing.
    else:
        webbrowser.open(url)

class TextBrowserKeyboardFocusFilter(QTextBrowser):
    """
    This is a QTextBrowser that only enables keyboard text selection when the focus reason is
    keyboard shortcuts or when a key is pressed while focused. Any other focus reason will
    deactivate keyboard text selection.
    """

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)

    def focusInEvent(self, e: QFocusEvent):
        if e.reason() in (Qt.TabFocusReason, Qt.BacktabFocusReason, Qt.ShortcutFocusReason):
            # Focused because of Tab, Shift+Tab or keyboard accelerator
            self.setTextInteractionFlags(self.textInteractionFlags() | Qt.TextSelectableByKeyboard)
        else:
            self.setTextInteractionFlags(self.textInteractionFlags() & ~Qt.TextSelectableByKeyboard)
        super().focusInEvent(e)

    def keyPressEvent(self, e: QKeyEvent):
        self.setTextInteractionFlags(self.textInteractionFlags() | Qt.TextSelectableByKeyboard)
        super().keyPressEvent(e)

if __name__ == "__main__":
    app = QApplication([])
    t = WaitingDialog(None, 'testing ...', lambda: [time.sleep(1)], lambda x: QMessageBox.information(None, 'done', "done"))
    t.start()
    app.exec_()
