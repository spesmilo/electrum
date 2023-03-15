#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2023 The Electrum Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import asyncio
import enum
import os.path
import time
import sys
import platform
import queue
import traceback
import os
import webbrowser
from decimal import Decimal
from functools import partial, lru_cache, wraps
from typing import (NamedTuple, Callable, Optional, TYPE_CHECKING, Union, List, Dict, Any,
                    Sequence, Iterable, Tuple, Type)

from PyQt5 import QtWidgets, QtCore
from PyQt5.QtGui import (QFont, QColor, QCursor, QPixmap, QStandardItem, QImage,
                         QPalette, QIcon, QFontMetrics, QShowEvent, QPainter, QHelpEvent, QMouseEvent)
from PyQt5.QtCore import (Qt, QPersistentModelIndex, QModelIndex, pyqtSignal,
                          QCoreApplication, QItemSelectionModel, QThread,
                          QSortFilterProxyModel, QSize, QLocale, QAbstractItemModel,
                          QEvent, QRect, QPoint, QObject)
from PyQt5.QtWidgets import (QPushButton, QLabel, QMessageBox, QHBoxLayout,
                             QAbstractItemView, QVBoxLayout, QLineEdit,
                             QStyle, QDialog, QGroupBox, QButtonGroup, QRadioButton,
                             QFileDialog, QWidget, QToolButton, QTreeView, QPlainTextEdit,
                             QHeaderView, QApplication, QToolTip, QTreeWidget, QStyledItemDelegate,
                             QMenu, QStyleOptionViewItem, QLayout, QLayoutItem, QAbstractButton,
                             QGraphicsEffect, QGraphicsScene, QGraphicsPixmapItem, QSizePolicy)

from electrum.i18n import _, languages
from electrum.util import FileImportFailed, FileExportFailed, make_aiohttp_session, resource_path
from electrum.util import EventListener, event_listener
from electrum.invoices import PR_UNPAID, PR_PAID, PR_EXPIRED, PR_INFLIGHT, PR_UNKNOWN, PR_FAILED, PR_ROUTING, PR_UNCONFIRMED
from electrum.logging import Logger
from electrum.qrreader import MissingQrDetectionLib

from .util import read_QIcon

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class MyMenu(QMenu):

    def __init__(self, config):
        QMenu.__init__(self)
        self.setToolTipsVisible(True)
        self.config = config

    def addToggle(self, text: str, callback, *, tooltip=''):
        m = self.addAction(text, callback)
        m.setCheckable(True)
        m.setToolTip(tooltip)
        return m

    def addConfig(self, text:str, name:str, default:bool, *, tooltip='', callback=None):
        b = self.config.get(name, default)
        m = self.addAction(text, lambda: self._do_toggle_config(name, default, callback))
        m.setCheckable(True)
        m.setChecked(b)
        m.setToolTip(tooltip)
        return m

    def _do_toggle_config(self, name, default, callback):
        b = self.config.get(name, default)
        self.config.set_key(name, not b)
        if callback:
            callback()


def create_toolbar_with_menu(config, title):
    menu = MyMenu(config)
    toolbar_button = QToolButton()
    toolbar_button.setIcon(read_QIcon("preferences.png"))
    toolbar_button.setMenu(menu)
    toolbar_button.setPopupMode(QToolButton.InstantPopup)
    toolbar_button.setFocusPolicy(Qt.NoFocus)
    toolbar = QHBoxLayout()
    toolbar.addWidget(QLabel(title))
    toolbar.addStretch()
    toolbar.addWidget(toolbar_button)
    return toolbar, menu



class MySortModel(QSortFilterProxyModel):
    def __init__(self, parent, *, sort_role):
        super().__init__(parent)
        self._sort_role = sort_role

    def lessThan(self, source_left: QModelIndex, source_right: QModelIndex):
        item1 = self.sourceModel().itemFromIndex(source_left)
        item2 = self.sourceModel().itemFromIndex(source_right)
        data1 = item1.data(self._sort_role)
        data2 = item2.data(self._sort_role)
        if data1 is not None and data2 is not None:
            return data1 < data2
        v1 = item1.text()
        v2 = item2.text()
        try:
            return Decimal(v1) < Decimal(v2)
        except:
            return v1 < v2

class ElectrumItemDelegate(QStyledItemDelegate):
    def __init__(self, tv: 'MyTreeView'):
        super().__init__(tv)
        self.tv = tv
        self.opened = None
        def on_closeEditor(editor: QLineEdit, hint):
            self.opened = None
            self.tv.is_editor_open = False
            if self.tv._pending_update:
                self.tv.update()
        def on_commitData(editor: QLineEdit):
            new_text = editor.text()
            idx = QModelIndex(self.opened)
            row, col = idx.row(), idx.column()
            edit_key = self.tv.get_edit_key_from_coordinate(row, col)
            assert edit_key is not None, (idx.row(), idx.column())
            self.tv.on_edited(idx, edit_key=edit_key, text=new_text)
        self.closeEditor.connect(on_closeEditor)
        self.commitData.connect(on_commitData)

    def createEditor(self, parent, option, idx):
        self.opened = QPersistentModelIndex(idx)
        self.tv.is_editor_open = True
        return super().createEditor(parent, option, idx)

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, idx: QModelIndex) -> None:
        custom_data = idx.data(MyTreeView.ROLE_CUSTOM_PAINT)
        if custom_data is None:
            return super().paint(painter, option, idx)
        else:
            # let's call the default paint method first; to paint the background (e.g. selection)
            super().paint(painter, option, idx)
            # and now paint on top of that
            custom_data.paint(painter, option.rect)

    def helpEvent(self, evt: QHelpEvent, view: QAbstractItemView, option: QStyleOptionViewItem, idx: QModelIndex) -> bool:
        custom_data = idx.data(MyTreeView.ROLE_CUSTOM_PAINT)
        if custom_data is None:
            return super().helpEvent(evt, view, option, idx)
        else:
            if evt.type() == QEvent.ToolTip:
                if custom_data.show_tooltip(evt):
                    return True
        return super().helpEvent(evt, view, option, idx)

    def sizeHint(self, option: QStyleOptionViewItem, idx: QModelIndex) -> QSize:
        custom_data = idx.data(MyTreeView.ROLE_CUSTOM_PAINT)
        if custom_data is None:
            return super().sizeHint(option, idx)
        else:
            default_size = super().sizeHint(option, idx)
            return custom_data.sizeHint(default_size)

class MyTreeView(QTreeView):

    ROLE_CLIPBOARD_DATA = Qt.UserRole + 100
    ROLE_CUSTOM_PAINT   = Qt.UserRole + 101
    ROLE_EDIT_KEY       = Qt.UserRole + 102
    ROLE_FILTER_DATA    = Qt.UserRole + 103

    filter_columns: Iterable[int]

    class BaseColumnsEnum(enum.IntEnum):
        @staticmethod
        def _generate_next_value_(name: str, start: int, count: int, last_values):
            # this is overridden to get a 0-based counter
            return count

    Columns: Type[BaseColumnsEnum]

    def __init__(
        self,
        *,
        parent: Optional[QWidget] = None,
        main_window: Optional['ElectrumWindow'] = None,
        stretch_column: Optional[int] = None,
        editable_columns: Optional[Sequence[int]] = None,
    ):
        parent = parent or main_window
        super().__init__(parent)
        self.main_window = main_window
        self.config = self.main_window.config if self.main_window else None
        self.stretch_column = stretch_column
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.create_menu)
        self.setUniformRowHeights(True)

        # Control which columns are editable
        if editable_columns is None:
            editable_columns = []
        self.editable_columns = set(editable_columns)
        self.setItemDelegate(ElectrumItemDelegate(self))
        self.current_filter = ""
        self.is_editor_open = False

        self.setRootIsDecorated(False)  # remove left margin
        self.toolbar_shown = False

        # When figuring out the size of columns, Qt by default looks at
        # the first 1000 rows (at least if resize mode is QHeaderView.ResizeToContents).
        # This would be REALLY SLOW, and it's not perfect anyway.
        # So to speed the UI up considerably, set it to
        # only look at as many rows as currently visible.
        self.header().setResizeContentsPrecision(0)

        self._pending_update = False
        self._forced_update = False

        self._default_bg_brush = QStandardItem().background()
        self.proxy = None # history, and address tabs use a proxy

    def create_menu(self, position: QPoint) -> None:
        pass

    def set_editability(self, items):
        for idx, i in enumerate(items):
            i.setEditable(idx in self.editable_columns)

    def selected_in_column(self, column: int):
        items = self.selectionModel().selectedIndexes()
        return list(x for x in items if x.column() == column)

    def get_role_data_for_current_item(self, *, col, role) -> Any:
        idx = self.selectionModel().currentIndex()
        idx = idx.sibling(idx.row(), col)
        item = self.item_from_index(idx)
        if item:
            return item.data(role)

    def item_from_index(self, idx: QModelIndex) -> Optional[QStandardItem]:
        model = self.model()
        if isinstance(model, QSortFilterProxyModel):
            idx = model.mapToSource(idx)
            return model.sourceModel().itemFromIndex(idx)
        else:
            return model.itemFromIndex(idx)

    def original_model(self) -> QAbstractItemModel:
        model = self.model()
        if isinstance(model, QSortFilterProxyModel):
            return model.sourceModel()
        else:
            return model

    def set_current_idx(self, set_current: QPersistentModelIndex):
        if set_current:
            assert isinstance(set_current, QPersistentModelIndex)
            assert set_current.isValid()
            self.selectionModel().select(QModelIndex(set_current), QItemSelectionModel.SelectCurrent)

    def update_headers(self, headers: Union[List[str], Dict[int, str]]):
        # headers is either a list of column names, or a dict: (col_idx->col_name)
        if not isinstance(headers, dict):  # convert to dict
            headers = dict(enumerate(headers))
        col_names = [headers[col_idx] for col_idx in sorted(headers.keys())]
        self.original_model().setHorizontalHeaderLabels(col_names)
        self.header().setStretchLastSection(False)
        for col_idx in headers:
            sm = QHeaderView.Stretch if col_idx == self.stretch_column else QHeaderView.ResizeToContents
            self.header().setSectionResizeMode(col_idx, sm)

    def keyPressEvent(self, event):
        if self.itemDelegate().opened:
            return
        if event.key() in [Qt.Key_F2, Qt.Key_Return, Qt.Key_Enter]:
            self.on_activated(self.selectionModel().currentIndex())
            return
        super().keyPressEvent(event)

    def mouseDoubleClickEvent(self, event: QMouseEvent):
        idx: QModelIndex = self.indexAt(event.pos())
        if self.proxy:
            idx = self.proxy.mapToSource(idx)
        if not idx.isValid():
            # can happen e.g. before list is populated for the first time
            return
        self.on_double_click(idx)

    def on_double_click(self, idx):
        pass

    def on_activated(self, idx):
        # on 'enter' we show the menu
        pt = self.visualRect(idx).bottomLeft()
        pt.setX(50)
        self.customContextMenuRequested.emit(pt)

    def edit(self, idx, trigger=QAbstractItemView.AllEditTriggers, event=None):
        """
        this is to prevent:
           edit: editing failed
        from inside qt
        """
        return super().edit(idx, trigger, event)

    def on_edited(self, idx: QModelIndex, edit_key, *, text: str) -> None:
        raise NotImplementedError()

    def should_hide(self, row):
        """
        row_num is for self.model(). So if there is a proxy, it is the row number
        in that!
        """
        return False

    def get_text_from_coordinate(self, row, col) -> str:
        idx = self.model().index(row, col)
        item = self.item_from_index(idx)
        return item.text()

    def get_role_data_from_coordinate(self, row, col, *, role) -> Any:
        idx = self.model().index(row, col)
        item = self.item_from_index(idx)
        role_data = item.data(role)
        return role_data

    def get_edit_key_from_coordinate(self, row, col) -> Any:
        # overriding this might allow avoiding storing duplicate data
        return self.get_role_data_from_coordinate(row, col, role=self.ROLE_EDIT_KEY)

    def get_filter_data_from_coordinate(self, row, col) -> str:
        filter_data = self.get_role_data_from_coordinate(row, col, role=self.ROLE_FILTER_DATA)
        if filter_data:
            return filter_data
        txt = self.get_text_from_coordinate(row, col)
        txt = txt.lower()
        return txt

    def hide_row(self, row_num):
        """
        row_num is for self.model(). So if there is a proxy, it is the row number
        in that!
        """
        should_hide = self.should_hide(row_num)
        if not self.current_filter and should_hide is None:
            # no filters at all, neither date nor search
            self.setRowHidden(row_num, QModelIndex(), False)
            return
        for column in self.filter_columns:
            filter_data = self.get_filter_data_from_coordinate(row_num, column)
            if self.current_filter in filter_data:
                # the filter matched, but the date filter might apply
                self.setRowHidden(row_num, QModelIndex(), bool(should_hide))
                break
        else:
            # we did not find the filter in any columns, hide the item
            self.setRowHidden(row_num, QModelIndex(), True)

    def filter(self, p=None):
        if p is not None:
            p = p.lower()
            self.current_filter = p
        self.hide_rows()

    def hide_rows(self):
        for row in range(self.model().rowCount()):
            self.hide_row(row)

    def create_toolbar(self, config):
        return

    def create_toolbar_buttons(self):
        hbox = QHBoxLayout()
        buttons = self.get_toolbar_buttons()
        for b in buttons:
            b.setVisible(False)
            hbox.addWidget(b)
        self.toolbar_buttons = buttons
        return hbox

    def create_toolbar_with_menu(self, title):
        return create_toolbar_with_menu(self.config, title)

    def show_toolbar(self, state, config=None):
        if state == self.toolbar_shown:
            return
        self.toolbar_shown = state
        for b in self.toolbar_buttons:
            b.setVisible(state)
        if not state:
            self.on_hide_toolbar()

    def toggle_toolbar(self, config=None):
        self.show_toolbar(not self.toolbar_shown, config)

    def add_copy_menu(self, menu: QMenu, idx) -> QMenu:
        cc = menu.addMenu(_("Copy"))
        for column in self.Columns:
            if self.isColumnHidden(column):
                continue
            column_title = self.original_model().horizontalHeaderItem(column).text()
            if not column_title:
                continue
            item_col = self.item_from_index(idx.sibling(idx.row(), column))
            clipboard_data = item_col.data(self.ROLE_CLIPBOARD_DATA)
            if clipboard_data is None:
                clipboard_data = item_col.text().strip()
            cc.addAction(column_title,
                         lambda text=clipboard_data, title=column_title:
                         self.place_text_on_clipboard(text, title=title))
        return cc

    def place_text_on_clipboard(self, text: str, *, title: str = None) -> None:
        self.main_window.do_copy(text, title=title)

    def showEvent(self, e: 'QShowEvent'):
        super().showEvent(e)
        if e.isAccepted() and self._pending_update:
            self._forced_update = True
            self.update()
            self._forced_update = False

    def maybe_defer_update(self) -> bool:
        """Returns whether we should defer an update/refresh."""
        defer = (not self._forced_update
                 and (not self.isVisible() or self.is_editor_open))
        # side-effect: if we decide to defer update, the state will become stale:
        self._pending_update = defer
        return defer

    def find_row_by_key(self, key) -> Optional[int]:
        for row in range(0, self.std_model.rowCount()):
            item = self.std_model.item(row, 0)
            if item.data(self.key_role) == key:
                return row

    def refresh_all(self):
        if self.maybe_defer_update():
            return
        for row in range(0, self.std_model.rowCount()):
            item = self.std_model.item(row, 0)
            key = item.data(self.key_role)
            self.refresh_row(key, row)

    def refresh_row(self, key: str, row: int) -> None:
        pass

    def refresh_item(self, key):
        row = self.find_row_by_key(key)
        if row is not None:
            self.refresh_row(key, row)

    def delete_item(self, key):
        row = self.find_row_by_key(key)
        if row is not None:
            self.std_model.takeRow(row)
        self.hide_if_empty()


