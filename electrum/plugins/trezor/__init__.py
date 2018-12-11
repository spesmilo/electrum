from electrum.i18n import _

fullname = 'Trezor Wallet'
description = _('Provides support for Trezor hardware wallet')
requires = [('trezorlib','github.com/trezor/python-trezor')]
registers_keystore = ('hardware', 'trezor', _("Trezor wallet"))
available_for = ['qt', 'cmdline']

