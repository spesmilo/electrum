from PyQt4.Qt import (QInputDialog, QLineEdit)
from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
from .digitalbitbox import DigitalBitboxPlugin


class Plugin(DigitalBitboxPlugin, QtPluginBase):
    icon_unpaired = ":icons/digitalbitbox_unpaired.png"
    icon_paired = ":icons/digitalbitbox.png"

    def create_handler(self, window):
        return DigitalBitbox_Handler(window)


class DigitalBitbox_Handler(QtHandlerBase):

    def __init__(self, win):
        super(DigitalBitbox_Handler, self).__init__(win, 'Digital Bitbox')
