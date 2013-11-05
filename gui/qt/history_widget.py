from PyQt4.QtGui import *
from electrum.i18n import _
from comma_separated import MyQLocale
from PyQt4.QtCore import QString

class HistoryWidget(QTreeWidget):

    def __init__(self, parent=None):
        QTreeWidget.__init__(self, parent)
        self.setColumnCount(2)
        self.setHeaderLabels([_("Amount"), _("To / From"), _("When")])
        self.setIndentation(0)

    def empty(self):
        self.clear()

    def append(self, address, amount, date):
    	locale = MyQLocale.system()
        if address is None:
          address = _("Unknown")
        if amount is None: 
          amount = _("Unknown")
        if date is None:
          date = _("Unknown")
        item = QTreeWidgetItem([amount, address, date])
        if amount.__class__ == str:
            amount = QString(amount)
        assert(amount.__class__ == QString)
        succeeds, amount_value = locale.toDecimal(amount)
        if succeeds and amount_value < 0:
          item.setForeground(0, QBrush(QColor("#BC1E1E")))
        self.insertTopLevelItem(0, item)

