from typing import TYPE_CHECKING
from PyQt5.QtQml import QQmlApplicationEngine
from electrum.plugin import hook, BasePlugin
from electrum.logging import get_logger

if TYPE_CHECKING:
    from electrum.gui.qml import ElectrumGui

class Plugin(BasePlugin):
    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)

    _logger = get_logger(__name__)

    @hook
    def init_qml(self, gui: 'ElectrumGui'):
        self._logger.debug('init_qml hook called')
