# Electrum  --  Lightweight Bitcoin Client

## Project Overview

Electrum is a lightweight Bitcoin wallet written in Python. Focuses on speed, low resource usage, and simplicity. Supports on-chain Bitcoin, Lightning Network, hardware wallets, and multi-signature. Pure Python core with native GUI options (Qt, QML).

## Architecture

### Core Package (`electrum/`)

71 Python modules in the main package. Key modules:

| Module | Purpose |
|--------|---------|
| `bitcoin.py` | Bitcoin primitives, transaction construction, signing |
| `wallet.py` | Wallet abstraction (Standard, Multisig, Imported, Hardware) |
| `keystore.py` | Key storage (BIP32, hardware, imported keys) |
| `commands.py` | CLI commands and RPC interface |
| `daemon.py` | Daemon process management |
| `interface.py` | Network server communication |
| `blockchain.py` | Blockchain header verification |
| `address_synchronizer.py` | Address history synchronization |
| `transaction.py` | Transaction parsing, signing, verification |
| `descriptor.py` | Output descriptors (miniscript) |
| `crypto.py` | Cryptographic operations (AES, HMAC) |
| `lnchannel.py` | Lightning channel state management |
| `lnpeer.py` | Lightning peer protocol handling |
| `lnrouter.py` | Lightning payment routing |
| `lnworker.py` | Lightning Network worker/coordinator |
| `lnmsg.py` | Lightning wire protocol messages |
| `invoices.py` | Invoice management (on-chain and Lightning) |
| `exchange_rate.py` | Fiat exchange rate integration |
| `i18n.py` | Internationalization |
| `dnssec.py` | DNSSEC verification for server discovery |
| `paymentrequest.py` | BIP70 payment request handling |

### GUI (`electrum/gui/`)

- `qt/`  --  Qt6-based GUI (full-featured)
- `qml/`  --  QML-based GUI (touch-friendly, Android)
- `text.py`  --  Terminal/text-mode interface
- `stdio.py`  --  JSON-RPC stdio interface
- `common_qt/`  --  Shared Qt utilities

### Network Layers

- `chains/`  --  Network configurations (mainnet, testnet, signet, testnet4, mutinynet)
- Servers defined in `electrum/chains/<network>/servers.json`
- Checkpoints in `electrum/chains/<network>/checkpoints.json`

### Testing

- `tests/`  --  Test suite (pytest-based)
- Coverage tracked at Coveralls

### Build & Packaging

- `contrib/`  --  Build scripts, OS packaging, localization
  - `contrib/build-wine/`  --  Windows builds
  - `contrib/osx/`  --  macOS builds
  - `contrib/android/`  --  Android builds (via python-for-android)
  - `contrib/locale/`  --  Translation tooling
- `setup.py` / `setup.cfg`  --  Python package configuration
- `pubkeys/`  --  Signing keys for release verification

## Build & Development

```bash
# Clone with submodules
git clone https://github.com/spesmilo/electrum.git
cd electrum
git submodule update --init

# Install (development mode)
python3 -m pip install --user -e .

# Run
./run_electrum

# Run tests
python3 -m pytest tests/

# Build translations (optional)
sudo apt-get install gettext
./contrib/locale/build_locale.sh electrum/locale/locale electrum/locale/locale
```

### Dependencies

```bash
# Core
sudo apt-get install libsecp256k1-dev python3-cryptography

# Qt GUI
sudo apt-get install python3-pyqt6

# With pip (skip libsecp compilation)
ELECTRUM_ECC_DONT_COMPILE=1 python3 -m pip install --user ".[gui,crypto]"
```

## Technology Stack

- **Language**: Python (>= 3.10)
- **GUI**: PyQt6, QML
- **Cryptography**: libsecp256k1, python-cryptography
- **Networking**: asyncio, stratum protocol
- **Serialization**: JSON, protobuf (for Lightning)

## Key Features

- SPV (Simplified Payment Verification)  --  doesn't download full blockchain
- Multi-signature wallets
- Hardware wallet support (Ledger, Trezor, BitBox, KeepKey, etc.)
- Lightning Network support
- Cold storage
- Seed phrase recovery (BIP39)
- Exchange rate integration
- Plug-in system

## Conventions

- MIT licensed
- Default branch: `master`
- Python modules are flat in `electrum/` (no deep subpackage nesting)
- GUI code separated into `electrum/gui/`
- Server protocol: Electrum's own stratum protocol over TCP/SSL
- Release signing keys in `pubkeys/`
- CI: Cirrus CI

## Network Protocol

Electrum uses its own lightweight server protocol (not Bitcoin P2P):
- Connects to Electrum servers listed in `chains/<network>/servers.json`
- Supports SSL/TLS and Tor connections
- SPV verification via merkle proofs
