from electrum.plugin import BasePlugin

class TimelockRecoveryPlugin(BasePlugin):
    VERSION = "v0.1.0"

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
