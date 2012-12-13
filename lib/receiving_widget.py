from PyQt4.QtGui import *
from PyQt4.QtCore import *
from i18n import _

class ReceivingWidget(QTreeWidget):

    def toggle_used(self):
        if self.hide_used:
            self.hide_used = False
            self.setColumnHidden(2, False)
        else:
            self.hide_used = True
            self.setColumnHidden(2, True)
        self.update_list()

    def edit_label(self, item, column):
      if column == 1 and item.isSelected():
        self.editing = True
        item.setFlags(Qt.ItemIsEditable|Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)
        self.editItem(item, column)
        item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsDragEnabled)
        self.editing = False

    def update_label(self, item, column):
      if self.editing: 
          return
      else:
          address = str(item.text(0))
          label = unicode( item.text(1) )
          self.owner.actuator.wallet.labels[address] = label

    def copy_address(self):
        address = self.currentItem().text(0)
        qApp.clipboard().setText(address)
        

    def update_list(self):

        self.clear()
        addresses = [addr for addr in self.owner.actuator.wallet.all_addresses() if not self.owner.actuator.wallet.is_change(addr)]
        for address in addresses:
            history = self.owner.actuator.wallet.history.get(address,[])

            used = "No"
            for tx_hash in history:
                tx = self.owner.actuator.wallet.transactions.get(tx_hash)
                if tx:
                    used = "Yes"

            if(self.hide_used == True and used == "No") or self.hide_used == False:
                label = self.owner.actuator.wallet.labels.get(address,'')
                item = QTreeWidgetItem([address, label, used])
                self.insertTopLevelItem(0, item)

    def __init__(self, owner=None):
        self.owner = owner
        self.editing = False

        QTreeWidget.__init__(self, owner)
        self.setColumnCount(3)
        self.setHeaderLabels([_("Address"), _("Label"), _("Used")])
        self.setIndentation(0)

        self.hide_used = True
        self.setColumnHidden(2, True)
        self.update_list()
