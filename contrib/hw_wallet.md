# Hardware wallets on Linux

The following aims to be a concise guide of what you need to get your hardware
wallet working with Electrum.


### 1. Dependencies

Currently all hardware wallets depend on `hidapi`, to be able to build that, you need:

```
sudo apt-get install libusb-1.0-0-dev libudev-dev
```

At least, these are the names of the packages on Ubuntu/Debian.
For other distros, you might need to find the corresponding packages.

### 2. Python libraries

Then depending on the device you have, you need a python package
(typically a library by the manufacturer):

<details>
 <summary>Trezor</summary>
 
```
python3 -m pip install trezor
```

For more details, refer to [python-trezor](https://github.com/trezor/python-trezor).
</details>

<details>
 <summary>Ledger</summary>
 
```
python3 -m pip install btchip-python
```

For more details, refer to [btchip-python](https://github.com/LedgerHQ/btchip-python).
</details>

<details>
 <summary>KeepKey</summary>
 
```
python3 -m pip install keepkey
```

For more details, refer to [python-keepkey](https://github.com/keepkey/python-keepkey).
</details>

<details>
 <summary>Digital Bitbox</summary>
 
 The Digital Bitbox does not have (or need) its own library but it still needs `hidapi`.
 
```
python3 -m pip install hidapi
```
</details>


### 3. udev rules


You will need to configure udev rules:


<details>
 <summary>Trezor</summary>
 
 See [link1](https://doc.satoshilabs.com/trezor-user/settingupchromeonlinux.html#manual-configuration-of-udev-rules)
 and [link2](https://raw.githubusercontent.com/trezor/trezor-common/master/udev/51-trezor.rules).
</details>

<details>
 <summary>Ledger</summary>
 
 See [link1](https://support.ledgerwallet.com/hc/en-us/articles/115005165269-What-to-do-if-my-Ledger-Nano-S-is-not-recognized-on-Windows-and-or-Linux-)
 and [link2](https://raw.githubusercontent.com/LedgerHQ/udev-rules/master/add_udev_rules.sh).
</details>

<details>
 <summary>KeepKey</summary>
 
 See [link1](https://support.keepkey.com/support/solutions/articles/6000037796-keepkey-wallet-is-not-being-recognized-by-linux)
 and [link2](https://raw.githubusercontent.com/keepkey/udev-rules/master/51-usb-keepkey.rules).
</details>

<details>
 <summary>Digital Bitbox</summary>
 
 See [link](https://shiftcrypto.ch/start_linux).
</details>

&nbsp;

Then reload udev rules (or reboot):


```
sudo udevadm control --reload-rules && sudo udevadm trigger
```

### 4. Done

That's it! Electrum should now detect your device.
