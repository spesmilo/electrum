from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from chipmixer import *

class Plugin(BasePlugin):
    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)

    @hook
    def init_menubar_tools(self, window, tools_menu):
        tools_menu.addAction(_("Tumble with ChipMixer"), partial(self.display_window, window))
        return

    def display_window(self, window):
        ChipMixer(window)
