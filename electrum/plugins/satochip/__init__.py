#from electrum.i18n import _

fullname = 'Satochip Wallet'
description = 'Provides support for Satochip hardware wallet'
requires = [('satochip', 'github.com/Toporin/pysatochip')]
registers_keystore = ('hardware', 'satochip', "Satochip wallet")
#registers_keystore = ('hardware', 'satochip', _("Satochip wallet"))
#available_for = ['qt', 'cmdline'] #+kivy?
available_for = ['qt']
