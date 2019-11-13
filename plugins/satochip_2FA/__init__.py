from electroncash.i18n import _

fullname = _('Satochip 2FA')
description = ' '.join([
    _("This plugin allows the use of a second factor to authorize transactions on a Satochip hardware wallet."),
    _("It sends and receives transaction challenge and response."),
    _("Data is encrypted and stored on a remote server.")
])
available_for = ['qt']
