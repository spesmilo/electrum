# udev rules

This directory contains all of the udev rules for the supported devices
as retrieved from vendor websites and repositories.
These are necessary for the devices to be usable on Linux environments.

 - `20-hw1.rules` (Ledger): https://github.com/LedgerHQ/udev-rules/blob/master/20-hw1.rules
 - `51-coinkite.rules` (Coldcard): https://github.com/Coldcard/ckcc-protocol/blob/master/51-coinkite.rules
 - `51-hid-digitalbitbox.rules`, `52-hid-digitalbitbox.rules` (Digital Bitbox): https://github.com/digitalbitbox/bitbox-wallet-app/blob/master/frontends/qt/resources/deb-afterinstall.sh
 - `53-hid-bitbox02.rules`, `54-hid-bitbox02.rules` (BitBox02): https://github.com/digitalbitbox/bitbox-wallet-app/blob/master/frontends/qt/resources/deb-afterinstall.sh
 - `51-trezor.rules` (Trezor): https://github.com/trezor/trezor-common/blob/master/udev/51-trezor.rules
 - `51-usb-keepkey.rules` (Keepkey): https://github.com/keepkey/udev-rules/blob/master/51-usb-keepkey.rules
 - `51-safe-t.rules` (Archos): https://github.com/archos-safe-t/safe-t-common/blob/master/udev/51-safe-t.rules

# Usage

Apply these rules by copying them to `/etc/udev/rules.d/` and notifying `udevadm`.
Your user will need to be added to the `plugdev` group, which needs to be created if it does not already exist.

```
$ sudo groupadd plugdev
$ sudo usermod -aG plugdev $(whoami)
$ sudo cp contrib/udev/*.rules /etc/udev/rules.d/
$ sudo udevadm control --reload-rules && sudo udevadm trigger
```
