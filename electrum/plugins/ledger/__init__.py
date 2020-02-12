from electrum.i18n import _

fullname = 'Ledger Wallet'
description = 'Provides support for Ledger hardware wallet'
requires = [('navhip', 'github.com/aguycalled/navhip-python')]
registers_keystore = ('hardware', 'ledger', _("Ledger wallet"))
available_for = ['qt', 'cmdline']
