from electrum.i18n import _


fullname = 'Hideez Wallet'
description = _('Provides support for Hideez hardware wallet')
requires = [('hideezlib', 'github.com/HideezGroup/python-hideez')]
registers_keystore = ('hardware', 'hideez', _("Hideez wallet"))
available_for = ['qt', 'cmdline']
