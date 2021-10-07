from PyQt5.QtCore import Qt
from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import (
    QMenu,
    QHeaderView,
    QTableWidget,
    QAbstractItemView,
)


class CustomTableWidget(QTableWidget):
    def __init__(
        self,
        column_names,
        resize_column=0,
        show_grid=False,
        starting_empty_cells=0,
        context_menu_options=None,
        *args,
        **kwargs,
    ):
        self.validate_columns_names(column_names=column_names)

        super().__init__(starting_empty_cells, len(column_names), *args, **kwargs)

        self._header_names = column_names
        self._context_menu_options = context_menu_options or []

        self._setup_self_context_menu()
        self._setup_self_table(resize_column=resize_column, show_grid=show_grid)

    @staticmethod
    def validate_columns_names(column_names):
        if not isinstance(column_names, list):
            raise ValueError('header names should be list')

        if not all((isinstance(header_name, str) for header_name in column_names)):
            raise ValueError('header names should be only string list')

    def _setup_self_table(self, resize_column, show_grid):
        self.setShowGrid(show_grid)
        self.verticalHeader().setVisible(False)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.setHorizontalHeaderLabels(self._header_names)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.customContextMenuRequested.connect(self.show_context_menu)
        self.horizontalHeader().setSectionResizeMode(resize_column, QHeaderView.Stretch)
        self.horizontalHeader().setDefaultAlignment(Qt.AlignCenter)
        self.setSortingEnabled(True)

    def _setup_self_context_menu(self):
        self.context_menu = QMenu()
        for menu_option in self._context_menu_options:
            self.context_menu.addAction(menu_option)

    def show_context_menu(self, *args, **kwargs):
        self.context_menu.popup(QCursor.pos())

    def setItem(self, row, column, item):
        item.setTextAlignment(Qt.AlignCenter)
        super().setItem(row, column, item)

    @property
    def column_names(self): # TODO - maybe rename as column names
        return self._header_names
