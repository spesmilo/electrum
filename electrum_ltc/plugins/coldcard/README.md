
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

Coldcard uses an emerging standard for unsigned tranasctions:

PSBT = Partially Signed Bitcoin Transaction = BIP174

However, this spec is still under heavy discussion and in flux. At
this point, the PSBT files generated will only be compatible with
Coldcard.

The Coldcard can be used 100% offline: it can generate a skeleton
Electrum wallet and save it to MicroSD card. Transport that file
to Electrum and it will fetch history, blockchain details and then
operate in "unpaired" mode.

Spending transactions can be saved to MicroSD using the "Export PSBT"
button on the transaction preview dialog (when this plugin is
owner of the wallet). That PSBT can be signed on the Coldcard
(again using MicroSD both ways). The result is a ready-to-transmit
bitcoin transaction, which can be transmitted using Tools > Load
Transaction > From File in Electrum or really any tool.

<https://coldcardwallet.com>

## TODO Items

- No effort yet to support translations or languages other than English, sorry.
- Coldcard PSBT format is not likely to be compatible with other devices, because the BIP174 is still in flux.
- Segwit support not 100% complete: can pay to them, but cannot setup wallet to receive them.
- Limited support for segwit wrapped in P2SH.
- Someday we could support multisig hardware wallets based on PSBT where each participant
  is using different devices/systems for signing, however, that belongs in an independant
  plugin that is PSBT focused and might not require a Coldcard to be present.

### Ctags

- I find this command useful (at top level) ... but I'm a VIM user.

    ctags -f .tags electrum `find . -name ENV -prune -o -name \*.py`


### Working with latest ckcc-protocol

- at top level, do this:

    pip install -e git+ssh://git@github.com/Coldcard/ckcc-protocol.git#egg=ckcc-protocol

- but you'll need the https version of that, not ssh like I can.
- also a branch name would be good in there
- do `pip uninstall ckcc` first
- see <https://stackoverflow.com/questions/4830856>
