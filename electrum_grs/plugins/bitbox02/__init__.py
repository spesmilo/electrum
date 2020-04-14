from electrum.i18n import _

fullname = "BitBox02"
description = (
    "Provides support for the BitBox02 hardware wallet"
)
requires = [
    (
        "bitbox02",
        "https://github.com/digitalbitbox/bitbox02-firmware/tree/master/py/bitbox02",
    )
]
registers_keystore = ("hardware", "bitbox02", _("BitBox02"))
available_for = ["qt"]
