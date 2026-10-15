import sys
from typing import TYPE_CHECKING, Optional

from PyQt6.QtCore import pyqtSignal, pyqtProperty, QObject

from electrum.logging import get_logger

if TYPE_CHECKING:
    from electrum.gui.qml import ElectrumQmlApplication
    from electrum.plugin import BasePlugin


class PluginQObject(QObject):
    logger = get_logger(__name__)

    pluginChanged = pyqtSignal()
    busyChanged = pyqtSignal()
    pluginEnabledChanged = pyqtSignal()

    def __init__(self, plugin: 'BasePlugin', parent: Optional['ElectrumQmlApplication']):
        super().__init__(parent)

        self._busy = False

        self.plugin = plugin
        self.app = parent

    @pyqtProperty(str, notify=pluginChanged)
    def name(self): return self._name

    @pyqtProperty(bool, notify=busyChanged)
    def busy(self): return self._busy

    # below only used for QML, not compatible yet with Qt

    @pyqtProperty(bool, notify=pluginEnabledChanged)
    def pluginEnabled(self): return self.plugin.is_enabled()

    @pluginEnabled.setter
    def pluginEnabled(self, enabled):
        if enabled != self.plugin.is_enabled():
            self.logger.debug(f'can {self.plugin.can_user_disable()}, {self.plugin.is_available()}')
            if not self.plugin.can_user_disable() and not enabled:
                return
            if enabled:
                self.app.plugins.enable(self.plugin.name)
            else:
                self.app.plugins.disable(self.plugin.name)
            self.pluginEnabledChanged.emit()

