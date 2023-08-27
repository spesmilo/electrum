from electrum.i18n import _

fullname = _('SwapServer')
description = """
Submarine swap server for an Electrum daemon.

Example setup:

  electrum -o setconfig use_swapserver True
  electrum -o setconfig swapserver_address localhost:5455
  electrum daemon -v

"""

available_for = ['cmdline']
