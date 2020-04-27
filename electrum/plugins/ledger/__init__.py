from electrum.i18n import _

fullname = 'Ledger Wallet'
description = 'Provides support for Ledger hardware wallet'
requires = [('btchip', 'github.com/ledgerhq/btchip-python'),('bitcoin', 'http://github.com/vbuterin/pybitcointools')]
registers_keystore = ('hardware', 'ledger', _("Ledger wallet"))
available_for = ['qt', 'cmdline']
