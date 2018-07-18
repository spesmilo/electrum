from electrum.i18n import _

fullname = 'Safe-T mini Wallet'
description = _('Provides support for Safe-T mini hardware wallet')
requires = [('safetlib','github.com/archos-safe-t/python-safet')]
registers_keystore = ('hardware', 'safe_t', _("Safe-T mini wallet"))
available_for = ['qt', 'cmdline']

