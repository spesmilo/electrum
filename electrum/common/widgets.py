from PyQt5.QtCore import Qt
from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import (
    QMenu,
    QAction,
    QHeaderView,
    QTableWidget,
    QAbstractItemView,
)
from PyQt5.QtWidgets import QTableWidgetItem


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
            menu_option_label: <method that need to be call on menu option click>.

            if nothing will happen on menu option click, just pass None:
                menu_option_label: None

            <method that need to be call on menu option click> need to take arguments:
                row_data, **context

            context can be whatever You want.
        """
        self._current_data = {}
        self._context_menu_kwargs = {}
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
            data_key: data_value[row_index]
            for data_key, data_value in self._current_data.items()
        }

    @staticmethod
    def _get_cell_item(value):
        item = QTableWidgetItem()
        item.setData(Qt.DisplayRole, value)

        return item

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
        context_menu_option_method = self._context_menu_options[self.sender().text()]
        if not context_menu_option_method:
            return

        context_menu_option_method(
            self._get_row_data(row_index=self.currentRow()), **self._context_menu_kwargs
        )

    def _clear_table_for_new_data(self, new_number_of_rows):
        self.setRowCount(new_number_of_rows)
        self.clearContents()

    def _clear_table_for_new_data(self, new_number_of_rows):
        self.setRowCount(new_number_of_rows)
        self.clearContents()

    def show_context_menu(self, *args, **kwargs):
        self.context_menu.popup(QCursor.pos())

    def setItem(self, row, column, item):
        item.setTextAlignment(Qt.AlignCenter)
        super().setItem(row, column, item)

    def insert_data(self, table_data: dict, context_menu_kwargs: dict = None):
        self._current_data = table_data

        self._clear_table_for_new_data(
            new_number_of_rows=max((len(data) for data in table_data.values()))
        )
        for column_name, column_data in self.current_table_data.items():
            for row_number, cell_data in enumerate(column_data):
                self.resizeColumnsToContents()
                self.setItem(
                    row_number,
                    self.column_names.index(column_name),
                    self._get_cell_item(value=cell_data),
                )

        if context_menu_kwargs:
            self._context_menu_kwargs = context_menu_kwargs

    @property
    def column_names(self):
        return self._header_names

    @property
    def current_table_data(self):
        return {
            data_key: data_value
            for data_key, data_value in self._current_data.items()
            if data_key in set(self.column_names)
        }
