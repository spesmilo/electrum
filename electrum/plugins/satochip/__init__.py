
fullname = 'Satochip Wallet'
description = 'Provides support for Satochip hardware wallet'
requires = [('satochip', 'github.com/Toporin/pysatochip')]
registers_keystore = ('hardware', 'satochip', "Satochip wallet")
available_for = ['qt']
