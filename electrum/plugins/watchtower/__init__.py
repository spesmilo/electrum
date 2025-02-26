from electrum.i18n import _

fullname = _('Watchtower')
description = """
A watchtower is a daemon that watches your channels and prevents the other party from stealing funds by broadcasting an old state.

Example:

daemon setup:

  electrum -o setconfig enable_plugin_watchtower True
  electrum -o setconfig watchtower_user wtuser
  electrum -o setconfig watchtower_password wtpassword
  electrum -o setconfig watchtower_port 12345
  electrum daemon -v

client setup:

  electrum -o setconfig watchtower_url http://wtuser:wtpassword@127.0.0.1:12345

"""

available_for = ['cmdline']
