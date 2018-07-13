from electrum_ltc.i18n import _

fullname = _('Revealer')
description = ''.join(["<br/>",
    "<b>"+_("Do you have something to hide ?")+"</b>", '<br/>', '<br/>',
    _("Revealer is a seed phrase back-up solution. It allows you to create a cold, analog, multi-factor backup of your wallet seeds, or of any arbitrary secret."), '<br/>', '<br/>',
    _("Using a Revealer is better than writing your seed phrases on paper: a revealer is invulnerable to physical access and allows creation of trustless redundancy."), '<br/>', '<br/>',
    _("This plug-in allows you to generate a pdf file of your secret phrase encrypted visually for your physical Revealer. You can print it trustlessly - it can only be decrypted optically with your Revealer."), '<br/>', '<br/>',
    _("The plug-in also allows you to generate a digital Revealer file and print it yourself on a transparent overhead foil."), '<br/>', '<br/>',
    _("Once activated you can access the plug-in through the icon at the seed dialog."), '<br/>', '<br/>',
    _("For more information, visit"),
    " <a href=\"https://revealer.cc\">https://revealer.cc</a>", '<br/>', '<br/>',
])
available_for = ['qt']


