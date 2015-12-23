from electrum.i18n import _

fullname = _('LabelSync')
description = '\n'.join([
    _("Synchronize your labels across multiple Electrum installs by using a remote database to save your data. Labels, transactions ids and addresses are encrypted before they are sent to the remote server."),
    _("The label sync's server software is open-source as well and can be found on github.com/maran/electrum-sync-server")
])
available_for = ['qt', 'kivy']

