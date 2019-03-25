from electrum.i18n import _

fullname = 'Coldcard Wallet'
description = 'Provides support for the Coldcard hardware wallet from Coinkite'
requires = [('ckcc-protocol', 'github.com/Coldcard/ckcc-protocol')]
registers_keystore = ('hardware', 'coldcard', _("Coldcard Wallet"))
available_for = ['qt', 'cmdline']
