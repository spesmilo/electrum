# To create a new GUI, please add its code to this directory.
# Three objects are passed to the ElectrumGui: config, daemon and plugins
# The Wallet object is instantiated by the GUI

# Notifications about network events are sent to the GUI by using network.register_callback()

from typing import TYPE_CHECKING, Mapping, Optional

from electrum import crandom
from electrum.crandom import CRANDOM_FEEDER_API

if TYPE_CHECKING:
    from . import qt
    from electrum.simple_config import SimpleConfig
    from electrum.daemon import Daemon
    from electrum.plugin import Plugins


class BaseElectrumGui:
    def __init__(self, *, config: 'SimpleConfig', daemon: 'Daemon', plugins: 'Plugins'):
        self.config = config
        self.daemon = daemon
        self.plugins = plugins

    def main(self) -> None:
        """Main entry point to GUI. Normally this launches a GUI event loop and 'blocks' this thread.
        The application will start to gracefully exit after this returns.
        """
        # Feed clock into crandom (again). This measures how long it took to create the GUI object.
        crandom.rand_add_refresh()
        # collect some GUI state as well:
        self.rand_add_gui_static_env(crandom.feed_entropy)

    def stop(self) -> None:
        """Stops the GUI.
        This method must be thread-safe.
        """
        pass

    @classmethod
    def version_info(cls) -> Mapping[str, Optional[str]]:
        return {}

    def rand_add_gui_static_env(self, feed: CRANDOM_FEEDER_API) -> None:
        """Gather non-cryptographic environment data, specific to the GUI, and feed that into crandom.
        Never raises.
        """
        pass
