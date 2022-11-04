from functools import partial

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QLabel, QVBoxLayout

from electrum.i18n import _
from electrum.plugin import hook
from electrum.wallet import Standard_Wallet
from electrum.gui.qt.util import WindowModalDialog


