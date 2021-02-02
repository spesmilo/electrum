# udev rules

This directory contains all of the udev rules for the supported devices
as retrieved from vendor websites and repositories.
These are necessary for the devices to be usable on Linux environments.

 - `20-hw1.rules` (Ledger): https://github.com/LedgerHQ/udev-rules/blob/master/20-hw1.rules

# Usage

Apply these rules by copying them to `/etc/udev/rules.d/` and notifying `udevadm`.
Your user will need to be added to the `plugdev` group, which needs to be created if it does not already exist.

```
$ sudo groupadd plugdev
$ sudo usermod -aG plugdev $(whoami)
$ sudo cp contrib/udev/*.rules /etc/udev/rules.d/
$ sudo udevadm control --reload-rules && sudo udevadm trigger
```
