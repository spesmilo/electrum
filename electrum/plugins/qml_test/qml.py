from typing import TYPE_CHECKING
from PyQt5.QtQml import QQmlApplicationEngine
from electrum.plugin import hook, BasePlugin
from electrum.logging import get_logger

if TYPE_CHECKING:
    from electrum.gui.qml import ElectrumGui

class Plugin(BasePlugin):
    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)

    @hook
    def init_qml(self, gui: 'ElectrumGui'):
        self.logger.debug('init_qml hook called')
