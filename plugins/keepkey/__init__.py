from electrum.i18n import _

fullname = 'KeepKey'
description = _('Provides support for KeepKey hardware wallet')
requires = [('keepkeylib','github.com/keepkey/python-keepkey')]
registers_keystore = ('hardware', 'keepkey', _("KeepKey wallet"))
available_for = ['qt', 'cmdline']
