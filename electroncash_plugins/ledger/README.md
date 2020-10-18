![Bitcoin Cash](https://raw.githubusercontent.com/The-Bitcoin-Cash-Fund/Branding/master/Bitcoin_Cash/BCH%20Logo%20Long%20Text%20WhiteBG.png "")
# Using Electron-Cash with Ledger Nano S

Successfully tested with Ledger Nano S (1.3.1) Electron-Cash (3.1.2) and Bitcoin Cash Ledger App (1.1.5)

---

### Official Links
[Product Website](https://www.ledgerwallet.com/products/ledger-nano-s)

##### Chrome Applications
[Ledger Manager](https://chrome.google.com/webstore/detail/ledger-manager/beimhnaefocolcplfimocfiaiefpkgbf)
[Leger Wallet Bitcoin](https://chrome.google.com/webstore/detail/ledger-wallet-bitcoin/kkdpmhnladdopljabkgpacgpliggeeaf)

##### Guides
[User Guide](https://ledger.zendesk.com/hc/en-us/sections/115001453109-Ledger-Nano-S)
[Ledger Bitcoin Cash App User Guide](https://ledger.zendesk.com/hc/en-us/sections/115001472725-Bitcoin-Cash)

---

### Requirements

To complete a Bitcoin Cash transactions with a Ledger Nano S, you will need:

1. An updated Ledger device - supported by Nano, HW.1, Nano S or Blue
2. Bitcoin Cash app installed on your Ledger device
3. "Browser Support" is disabled in the Bitcoin Cash Ledger app (only required for Nano S and/or Blue)

PLEASE NOTE: Ensure that you do not have another application (like Electrum, Bitcoin Core, or any other software) opened on your computer

(Use the Ledger Manager Chrome application to download and install the Bitcoin Cash app onto your Ledger device)

---

### Firmware

The latest Nano S firmware was released on March 2017 (Secure Element 1.3.1)

It is strongly recommended to upgrade to the latest firmware. 

To check which firmware version your Nano S is currently running, open the "Settings" application on your device and scroll until "Firmware" is displayed. 
Press both buttons to enter the menu which displays your firmware version. 

Firmware Update Guide: https://ledger.zendesk.com/hc/en-us/articles/115005165409-How-can-I-update-my-Nano-S-

---

### Bitcoin Cash Ledger App

Install the Ledger Manager to download and install Bitcoin Cash application onto your Ledger device.

---

### Using Ledger Nano S with Electron-Cash

1. Connect your Ledger device to USB
2. Enter your PIN code
3. Open the Bitcoin Cash application on the Ledger (required for Nano S and Blue)
4. Disable the "Browser support" setting in this application (required for Nano S and Blue)
5. Launch Electron-Cash and start the new wallet wizard:
    * Select "Use a Hardware Device" - press Next
    * Select your Ledger device - press Next
    * Select your desired Wallet Derivation (or leave default value for Bitcoin Cash)
       - If you want to use legacy Bitcoin addresses use m/44'/0'/0'
       - If you want to use Bitcoin Cash addresses use m/44'/145'/0'
6. ???
7. PROFIT!!! (Your Bitcoin wallet should now open in Electron-Cash)

---

### Troubeshooting

1. Uninstall and reinstall the Bitcoin Cash app on your Ledger device
2. Try a different USB cable
3. Try a different USB port 
4. Try on another computer (see compatibility)
