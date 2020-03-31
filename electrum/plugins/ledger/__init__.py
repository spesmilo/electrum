from electrum.i18n import _

fullname = 'Ledger Wallet'
description = 'Provides support for Ledger hardware wallet for Syscoin'
requires = [('btchip', 'github.com/syscoin/btchip-python')]
registers_keystore = ('hardware', 'ledger', _("Ledger wallet"))
available_for = ['qt', 'cmdline']
