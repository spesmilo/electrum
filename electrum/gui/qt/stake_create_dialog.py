from typing import TYPE_CHECKING

from PyQt5.QtWidgets import (QLabel, QVBoxLayout, QGridLayout, QCompleter, QHBoxLayout, QWidget)

from electrum.i18n import _
from .util import (WindowModalDialog, HelpLabel, EnterButton, )


class CreateStaking(WindowModalDialog):

    def __call__(self, *args, **kwargs):
        self.show()

    def __init__(self, parent, title):
        WindowModalDialog.__init__(self, parent)

        self.setMinimumWidth(400)
        self.setWindowTitle(title)
        self.vbox = QVBoxLayout()
        self.send_grid = grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnStretch(3, 1)

    def reset_max(self):
        pass

    def spend_max(self):
        pass

