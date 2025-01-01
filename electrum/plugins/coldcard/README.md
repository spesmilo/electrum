# Coldcard Hardware Wallet Plugin

## Just the glue please

This code connects the public USB API and Electrum. Leverages all
the good work that's been done by the Electrum team to support
hardware wallets.

## Background

The Coldcard has a larger screen (128x64) and a number pad. For
this reason, all PIN code entry is done directly on the device.
Coldcard does not appear on the USB bus until unlocked with appropriate
PIN. Initial setup, and seed generation must be done offline.

Coldcard uses the standard for unsigned transactions:

PSBT = Partially Signed Bitcoin Transaction = BIP174

The Coldcard can be used 100% offline: it can generate a skeleton
Electrum wallet and save it to MicroSD card. Transport that file
to Electrum and it will fetch history, blockchain details and then
operate in "unpaired" mode.

Spending transactions can be saved to MicroSD using by exporting them
from transaction preview dialog (when this plugin is
owner of the wallet). That PSBT is then signed on the Coldcard
(again using MicroSD both ways). The result is a ready-to-transmit
bitcoin transaction, which can be transmitted using Tools > Load
Transaction > From File in Electrum or really any tool.

<https://coldcardwallet.com>

## TODO Items

- No effort yet to support translations or languages other than English, sorry.
- We support multisig hardware wallets based on PSBT where each participant
  is using different devices/systems for signing.

### Ctags

- I find this command useful (at top level) ... but I'm a VIM user.

    ctags -f .tags electrum `find . -name ENV -prune -o -name \*.py`

