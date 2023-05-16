from PyQt5.QtCore import pyqtSignal, pyqtProperty, QSortFilterProxyModel, QModelIndex

from electrum.logging import get_logger

class QEFilterProxyModel(QSortFilterProxyModel):
    _logger = get_logger(__name__)

    def __init__(self, parent_model, parent=None):
        super().__init__(parent)
        self._filter_value = None
        self.setSourceModel(parent_model)

    countChanged = pyqtSignal()
    @pyqtProperty(int, notify=countChanged)
    def count(self):
        return self.rowCount(QModelIndex())

    def isCustomFilter(self):
        return self._filter_value is not None

    def setFilterValue(self, filter_value):
        self._filter_value = filter_value

    def filterAcceptsRow(self, s_row, s_parent):
        if not self.isCustomFilter:
            return super().filterAcceptsRow(s_row, s_parent)

        parent_model = self.sourceModel()
        d = parent_model.data(parent_model.index(s_row, 0, s_parent), self.filterRole())
        return True if self._filter_value is None else d == self._filter_value
