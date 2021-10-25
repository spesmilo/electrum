from functools import partial

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import (
    QMenu,
    QAction,
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
        """
        context_menu_options - it is a dictionary.
                menu_option_label: <method that need to be call on menu option click.

            if nothing will happen on menu option click, just pass None:
                menu_option_label: None
        """
        self.validate_columns_names(column_names=column_names)

        super().__init__(starting_empty_cells, len(column_names), *args, **kwargs)

        self._header_names = column_names
        self._context_menu_options = context_menu_options or {}

        self._setup_self_context_menu()
        self._setup_self_table(resize_column=resize_column, show_grid=show_grid)

    @staticmethod
    def validate_columns_names(column_names):
        if not isinstance(column_names, list):
            raise ValueError('header names should be list')

        if not all((isinstance(header_name, str) for header_name in column_names)):
            raise ValueError('header names should be only string list')

    def _get_row_data(self, row_index):
        return {
            column_name: self.item(row_index, column_index).text()
            for column_index, column_name in enumerate(self._header_names)
        }

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

        for menu_option_label, menu_option_method in self._context_menu_options.items():
            menu_option_action = QAction(menu_option_label, self)
            self.context_menu.addAction(menu_option_action)
            menu_option_action.triggered.connect(self._call_context_menu_option_method)

    def _call_context_menu_option_method(self):
        self._context_menu_options[self.sender().text()](
            self._get_row_data(row_index=self.currentRow())
        )

    def show_context_menu(self, *args, **kwargs):
        self.context_menu.popup(QCursor.pos())

    def setItem(self, row, column, item):
        item.setTextAlignment(Qt.AlignCenter)
        super().setItem(row, column, item)

    @property
    def column_names(self):  # TODO - maybe rename as column names
        return self._header_names
