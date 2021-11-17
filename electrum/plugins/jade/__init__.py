from electrum.i18n import _

fullname = 'Blockstream Jade Wallet'
description = 'Provides support for the Blockstream Jade hardware wallet'
#requires = [('', 'github.com/')]
registers_keystore = ('hardware', 'jade', _("Jade wallet"))
available_for = ['qt', 'cmdline']
