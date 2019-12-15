from electrum.i18n import _

fullname = _('NavShuffle')
description = ''.join([
    _('Protect your privacy and anonymize your coins (UTXOs) by shuffling them with other users of NavShuffle.'), "\n\n",
    _('A layered encryption scheme is used so that none of the participants know the outputs of the other participants.'), " ",
    _('In addition, a blame protocol is used to mitigate time-wasting denial-of-service type attacks.')
])
available_for = ['qt']
