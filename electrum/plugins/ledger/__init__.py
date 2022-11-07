from electrum.i18n import _

fullname = 'Ledger Wallet'
description = 'Provides support for Ledger hardware wallet'
requires = [('ledger_bitcoin', 'github.com/LedgerHQ/app-bitcoin-new')]
registers_keystore = ('hardware', 'ledger', _("Ledger wallet"))
available_for = ['qt', 'cmdline']
