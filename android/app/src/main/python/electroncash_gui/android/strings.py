# This file lists translatable strings used in the Android app which don't appear anywhere else
# in the Electron Cash repository. Some of them only differ in capitalization or punctuation:
# see https://medium.com/@jsaito/making-a-case-for-letter-case-19d09f653c98
#
# If you change this file, you'll need to rebuild the strings.xml files by following the
# instructions in android/README.md.
#
# Please keep the strings in alphabetical order.

# This file is never actually imported, but keep syntax checkers happy.
from gettext import gettext as _, ngettext

ngettext("%d address", "%d addresses", 1)
_("Are you sure you want to delete your wallet \'%s\'?")
_("BIP39 seed")
_("Block explorer")
_("Cannot specify private keys and addresses in the same wallet.")
_("Change password")
_("Close wallet")
_("Confirm password")
_("Console")
_("Copyright © 2017-2021 Electron Cash LLC and the Electron Cash developers.")
_("Current password")
_("Delete wallet")
_("Derivation invalid")
_("Disconnect")
_("Do you want to close this wallet?")
_("Enter password")
_("Export wallet")
_("Filenames cannot contain the '/' character. Please enter a different filename to proceed.")
_("For support, please visit us on <a href='https://github.com/Electron-Cash/Electron-Cash/issues'>"
  "GitHub</a> or on <a href='https://t.me/electroncashwallet'>Telegram</a>.")
_("ID")
_("Import addresses or private keys")
_("Invalid address")
_("Load transaction")
_("Made with <a href='https://chaquo.com/chaquopy'>Chaquopy</a>, the Python SDK for Android.")
_("New password")
_("New wallet")
_("No wallet is open.")
_("No wallet")
_("Not a valid address or private key: '%s'")
_("Passphrase")
_("Press the menu button above to open or create one.")
_("Rename wallet")
_("Request")
_("Restore from seed")
_("Save transaction")
_("Show seed")
_("Size")
_("Signed transaction")
_("The string you entered has been broadcast. Please check your transactions for confirmation.")
_("Transaction not found")
_("%1$d tx (%2$d unverified)")
_("Type, paste, or scan a valid signed transaction in hex format below:")
_("Use a master key")
_("Wallet name is too long")
_("Wallet names cannot contain the '/' character. Please enter a different wallet name to proceed.")
_("Wallet exported successfully")
_("Wallet renamed successfully")
_("Wallet seed")
_("You don't have any contacts.")
