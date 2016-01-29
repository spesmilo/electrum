from electrum.i18n import _

fullname = 'Ledger Wallet'
description = _('Provides support for Ledger hardware wallet')
requires = [('btchip','github.com/ledgerhq/btchip-python')]
requires_wallet_type = ['ledger']
registers_wallet_type = ('hardware', 'ledger', _("Ledger wallet"))
available_for = ['qt', 'cmdline']

