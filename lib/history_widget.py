from PyQt4.QtGui import *
from i18n import _

class HistoryWidget(QTreeWidget):

    def __init__(self, parent=None):
        QTreeWidget.__init__(self, parent)
        self.setColumnCount(2)
        self.setHeaderLabels([_("Amount"), _("To / From")])
        self.setIndentation(0)

    def append(self, address, amount):
        if amount >= 0:
            display_amount = "+%s" % amount
        else:
            display_amount = "-%s" % (-amount)
        item = QTreeWidgetItem([display_amount, address])
        self.insertTopLevelItem(0, item)

