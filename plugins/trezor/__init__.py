from electrum_ltc.i18n import _

fullname = 'Trezor Wallet'
description = _('Provides support for Trezor hardware wallet')
requires = [('trezorlib','github.com/trezor/python-trezor')]
requires_wallet_type = ['trezor']
registers_wallet_type = ('hardware', 'trezor', _("Trezor wallet"))
available_for = ['qt', 'cmdline']

