# To create a new GUI, please add its code to this directory.
# Three objects are passed to the ElectrumGui: config, daemon and plugins
# The Wallet object is instantiated by the GUI

# Notifications about network events are sent to the GUI by using network.register_callback()

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import qt
    from . import kivy
