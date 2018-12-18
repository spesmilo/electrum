from electrum.i18n import _

fullname = _('Two Factor Authentication')
description = ''.join([
    _("This plugin adds two-factor authentication to your wallet."), '<br/>',
    _("For more information, visit"),
    " <a href=\"https://api.trustedcoin.com/#/electrum-help\">https://api.trustedcoin.com/#/electrum-help</a>"
])
requires_wallet_type = ['2fa']
registers_wallet_type = '2fa'
available_for = ['qt', 'cmdline', 'kivy']
