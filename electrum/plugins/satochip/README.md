# Satochip plugin for Electrum

## Purpose

This plugin adds support for the [Satochip hardware wallet](https://satochip.io)
to Electrum. The Satochip card is a Javacard/smartcard signing device (see
[SatochipApplet](https://github.com/Toporin/SatochipApplet)); the private keys
never leave the card and every transaction must be signed on it, after PIN
verification.

The plugin is self-contained:

- `card.py` -- the card connector, a stripped-down port of
  [pysatochip](https://github.com/Toporin/pysatochip) limited to the Satochip
  applet: card detection, PIN management, card setup, BIP39 seed import, BIP32
  key derivation, message and transaction signing, secure channel, and card
  authenticity checks. It does **not** include SeedKeeper, Satodime, Satocash,
  2FA, NDEF or factory-reset support.
- `certificate.py` -- device certificate chain validation using only the
  `cryptography` library, with the Satochip production and test PKI
  root/subCA certificates embedded.

**Dependencies**: `pyscard` (PC/SC smartcard transport) and `cryptography`
(already an Electrum dependency). Nothing else.

**Feature scope**: wallet creation wizard for new or uninitialized cards (PIN
setup, BIP39 seed import with optional passphrase), standard/singlesig and
multisig wallets, transaction and message signing, and a settings dialog
(change PIN, reset seed, verify card authenticity, change card label).
Cards with 2FA enabled are refused with an explanatory message. If the PIN is
entered wrongly too many times, the card bricks itself; funds are then only
recoverable from the seed backup.

The plugin can be used in two ways:

- **internal plugin**: shipped inside the Electrum source tree / binaries
  (`electrum/plugins/satochip/`), where it works out of the box;
- **external plugin**: distributed as a `.zip` file that users import into a
  stock Electrum installation, as described below.

## Building the external plugin zip

From the root of the Electrum source tree:

```bash
./contrib/make_plugin electrum/plugins/satochip
```

This creates `satochip-<version>.zip` in the current directory, with
`<version>` taken from `manifest.json`. Bump the `version` field in
`manifest.json` before each release so users get a distinct file and Electrum
offers the upgrade.

After building, record and publish the archive hash -- users will compare it
with the hash shown in the install dialog:

```bash
sha256sum satochip-<version>.zip
```

## User guide: installing the external plugin

### Requirements

- Electrum >= 4.8.0, **running from source or from a pip installation**.
  The official frozen binaries (AppImage, Windows, macOS executables) cannot
  load external dependencies, so the plugin cannot work there: `pyscard`
  must be importable from Electrum's Python environment.
- `pyscard` installed in that environment:

  ```bash
  python3 -m pip install pyscard
  ```

  On Linux you additionally need the PC/SC daemon and library, e.g.
  `sudo apt-get install pcscd libpcsclite-dev` (pyscard is built with
  `swig` if no wheel is available). On Windows and macOS, PC/SC is part of
  the OS.
- A smartcard reader with a Satochip card.

### 1. Add the plugin

In Electrum, go to **Tools -> Plugins** and click **Add**, then select the
`satochip-<version>.zip` file. (Alternatively, when creating a new wallet,
the hardware wallet selection page also has an **Add plugin** button.)

A dialog shows the plugin name, author, version, its dependency
(`pyscard`) and the archive's **sha256 hash**. Compare this hash with the one
published with the release before proceeding.

### 2. Authorize the plugin

External plugins run with the same privileges as Electrum itself, so
installing one requires explicit authorization: click **Install** and enter
your **plugin authorization password**.

The first time you install any external plugin, Electrum asks you to create
this password. It is separate from your wallet password; its purpose is to
prevent other users or malware from silently installing plugins. The
corresponding public key is stored in an administrator-owned location
(`/etc/electrum/plugins_key` on Linux, the `HKLM` registry hive on Windows,
a root-owned file on macOS), which is why setup may ask for administrator
rights.

Once authorized, the plugin is trusted permanently on this machine: it loads
automatically at startup. Hardware wallet plugins have no enable/disable
toggle and do not appear in the regular plugin list.

### 3. Use the plugin

Plug in your Satochip card, then create a new wallet (**File ->
New/Restore**) and choose a hardware wallet: **Satochip** appears in the
device scan. If the card has never been initialized, the wizard walks you
through setting a PIN and importing a BIP39 seed. Back up the seed securely:
it is the only way to recover funds if the card is lost or bricked.

### 4. Update the plugin

Updates are manual; there is no auto-update:

1. Download the new `satochip-<version>.zip`.
2. Go to **Tools -> Plugins -> Add** and select the new zip.
3. Click **Upgrade** and enter the plugin authorization password again (the
   archive hash changed, so a fresh authorization is required).
4. **Restart Electrum** -- the old version keeps running in memory until then.

Plugin settings and your wallet files are preserved across upgrades.

### 5. Reinstall or remove

To reinstall, simply import the zip again (same flow as an update).

To remove the plugin: **Tools -> Plugins**, click on **Satochip Wallet**,
then **Remove**, and restart Electrum. Wallets that use a Satochip keystore
cannot be opened while the plugin is removed or unauthorized; reinstalling
and re-authorizing the plugin restores access. Your seed backup always
remains the ultimate fallback.

### Forgotten authorization password

If you lose the plugin authorization password, enter a wrong one once: the
error dialog shows the key file location and offers a **Try Auto-Reset**
button that deletes it (administrator rights required). You can then set a
new password. This does not affect already-installed plugins' wallet data,
but plugins will need to be authorized again.

## Security notes

- Treat the zip with care: only install archives whose sha256 hash matches
  the one you published/downloaded from a trusted source. Authorization
  proves consent, not that the code is trustworthy.
- Never enter your seed or PIN on a website or in another application. The
  PIN is only ever requested by Electrum dialogs after the card is inserted.
- The card connector logs card traffic at debug level with secret fields
  (PIN, seed, signatures payload) masked.

## Links

- Satochip: https://satochip.io
- Satochip applet: https://github.com/Toporin/SatochipApplet
- Electrum plugin development: https://plugins.electrum.org/developers.html
