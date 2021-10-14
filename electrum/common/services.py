from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidgetItem


class CustomTableWidgetController:
    def __init__(self, table_widget):
        self._current_data = {}
        self._table_widget = table_widget

    @staticmethod
    def _get_cell_item(value):
        item = QTableWidgetItem()
        item.setData(Qt.DisplayRole, value)

        return item

    def validate_table_data(self, table_data):
        if not isinstance(table_data, dict):
            raise ValueError('table data should be dict')

        if set(table_data.keys()) != set(self._table_widget.column_names):
            raise ValueError(
                f'table data keys are '
                f'not equal to table column names: {self._table_widget.column_names}'
            )

    def _clear_table_for_new_data(self, new_number_of_rows):
        self._table_widget.setRowCount(new_number_of_rows)
        self._table_widget.clearContents()

    def insert_data(self, table_data):
        self.validate_table_data(table_data=table_data)

        self._clear_table_for_new_data(
            new_number_of_rows=max((len(data) for data in table_data.values()))
        )
        for column_name, column_data in table_data.items():
            for row_number, cell_data in enumerate(column_data):
                self._table_widget.resizeColumnsToContents()
                self._table_widget.setItem(
                    row_number,
                    self._table_widget.column_names.index(column_name),
                    self._get_cell_item(value=cell_data)
                )

    @property
    def current_data(self):
        return self._current_data
