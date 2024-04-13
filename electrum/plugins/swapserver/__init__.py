from electrum.i18n import _

fullname = _('SwapServer')
description = """
Submarine swap server for an Electrum daemon.

Example setup:

  electrum -o setconfig enable_plugin_swapserver True
  electrum -o setconfig swapserver_port 5455
  electrum daemon -v

"""

available_for = ['cmdline']
