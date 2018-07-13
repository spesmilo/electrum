from electrum_ltc.i18n import _

fullname = 'TREZOR Wallet'
description = _('Provides support for TREZOR hardware wallet')
requires = [('trezorlib','github.com/trezor/python-trezor')]
registers_keystore = ('hardware', 'trezor', _("TREZOR wallet"))
available_for = ['qt', 'cmdline']

