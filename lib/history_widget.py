from PyQt4.QtGui import *
from i18n import _

class HistoryWidget(QTreeWidget):

    def __init__(self, parent=None):
        QTreeWidget.__init__(self, parent)
        self.setColumnCount(2)
        self.setHeaderLabels([_("Amount"), _("To / From")])
        self.setIndentation(0)

    def append(self, address, amount):
        item = QTreeWidgetItem([amount, address])
        self.insertTopLevelItem(0, item)

