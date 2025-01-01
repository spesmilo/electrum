from electrum.i18n import _

fullname = _('Watchtower')
description = """
Watchtower for Electrum.

Example setup:

  electrum -o setconfig enable_plugin_watchtower True
  electrum -o setconfig watchtower_user wtuser
  electrum -o setconfig watchtower_password wtpassword
  electrum -o setconfig watchtower_port 12345
  electrum daemon -v

"""

available_for = ['cmdline']
