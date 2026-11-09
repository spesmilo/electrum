# Threat model: Electrum

Please rate strictly against the rubric below. If a finding is not clearly at a level, rate it lower. A
critical report should include a reproducer: a unit test under `tests/` or a script against a local
regtest network.

## What Electrum is

Electrum is a Bitcoin wallet written in Python: a light (SPV) client that gets the chain from Electrum
servers, plus a Lightning node. It runs as a desktop GUI, a mobile GUI, and a command line client with a
daemon. Users hold real funds on mainnet. Keys are kept on the user's machine, or on a hardware wallet.

Electrum is a high-value target. Its users have been phished through malicious servers before (#4968),
and attackers are likely to go after its supply chain.

## Where untrusted input enters

Treat every party Electrum talks to, and anything a user can be tricked into loading, as attacker
controlled:

- **Electrum servers**: everything they send. Servers are trusted for availability, not for integrity:
  Electrum checks block headers for proof of work and the wallet's transactions against merkle proofs.
- **The Lightning network**: peers, and anything that reaches Electrum through the network (messages,
  onions, payment and routing data), whatever routing mode is in use.
- **Counterparties and remote services**: anyone the wallet transacts or coordinates with, such as swap
  providers, and any service Electrum or a bundled plugin reaches over HTTP, Nostr, DNS or similar.
- **Data the user pastes, scans, opens or imports**: addresses, payment URIs, invoices, responses fetched
  while resolving a payment request, transactions and PSBTs, and exported wallet data and backups.
- **Hardware wallets**: their responses are untrusted with respect to the host. A device that lies about
  its own keys is out of scope.
- **Translations**: volunteers write them on Crowdin, and they reach Electrum through the `electrum/locale`
  submodule. Treat every translated string as attacker controlled.
- **The supply chain**: everything Electrum and its release binaries are built from, such as Python
  packages, native libraries built from source, Docker base images and distribution packages, submodules,
  and the GitHub Actions and other tools CI runs. Only what is pinned by hash or commit and verified is
  trusted. Anything fetched by name, version, tag, branch or URL alone can be swapped by an attacker.

Trusted: the Electrum maintainers, the user, the operating system account running Electrum, and a
correctly entered wallet password.

## Security boundaries that must hold

- Private keys and seeds never leave the process unless the user explicitly exports them.
- What the user confirms (recipients, amounts, fee, change) is what gets signed.
- Encrypted wallet data reveals nothing useful without its password.
- Local interfaces that control the wallet, such as the daemon's RPC, answer only callers with their
  credentials. Other local users and websites in the user's browser cannot use them.
- The mechanisms that restrict what code loads into the wallet, such as the authorization of external
  plugins, hold even against malware running as the user without elevated privileges.
- Lightning: the wallet can always enforce its latest channel state on chain in time, and never releases a
  secret or signature that lets someone take funds the wallet does not owe them.
- Only the maintainers decide what code goes into a release binary. Release binaries are built from the
  tagged source and the pinned, verified inputs it names, and reproducibly, so independent builders can
  check them.

## How we rate severity

**Critical**:

- Theft or permanent loss of the user's funds, caused by any of the untrusted inputs above, with no
  unusual user action beyond normal use. Examples: Electrum signs a transaction that pays the attacker, or
  burns funds as fee without showing it; a peer gets an outdated or invalid channel state accepted, or
  broadcasts a revoked state without being punished; an HTLC or swap is lost to the counterparty.
- Disclosure of private keys, seeds or the wallet password to a remote party, or into files or logs that
  others can read. Weak or repeated randomness in key or nonce generation.
- Remote code execution triggered by any of the inputs above.
- A bypass of one of the boundaries above.
- A difference, controlled by an attacker, between what the user is shown and confirms and what is signed.
- Phishing: text from a remote party or a translator shown to the user in a way that can trick them into a
  harmful action, such as visiting a site, installing software, entering their seed, or sending funds.
  Examples: a server's error message shown in a dialog (`sanitize_tx_broadcast_response` in
  `interface.py` shows how broadcast errors are handled instead), remote or translated text rendered as
  rich text with a clickable link, a translation that adds a URL or an instruction that is not in the
  English source.
- Supply chain: a way for anyone other than the maintainers to get code into a release binary, or to get
  credentials that would let them do so or change translations. Examples: a download in a build script,
  Dockerfile or CI workflow without a pinned hash or commit; a pin to something that can change (a tag, a
  branch, `latest`); a signature or hash check that can be skipped or fails open; a CI job that runs code
  from a pull request while holding such credentials; an update announcement accepted without a valid
  signature.

**High** (a real security bug short of critical; listed so you do not rate these critical):

- Denial of service: a crash, hang, or memory or CPU exhaustion caused by a server, peer or input, **unless**
  it leads to loss of funds. Example: it stops the wallet from enforcing a channel state before a deadline,
  and the user cannot avoid this by restarting or changing server.
- A peer force-closing a channel, or a payment failing, without loss of funds.
- Release builds that are no longer reproducible, or a pin or check in the build weakened without a
  concrete way to exploit it.
- Privacy leaks. The Electrum protocol shows the server the wallet's addresses by design, and Lightning
  reveals some information to peers and routing nodes. Leaks beyond that are high, for example a request
  that links the wallet's addresses to each other or to the user.
- Untrusted input not fully checked in one of the components that matter most, where no path to a critical
  impact is shown. Examples: a server or Lightning message that is not fully validated, unsafe parsing or
  deserialization, injection or path traversal, a race in wallet or channel state, an overflow or rounding
  error in amounts or fees.

**Medium or lower**:

- Anything that needs an attacker with code execution as the user, write access to the user's data
  directory, or physical access, except where a boundary above says otherwise.

## Inherent to the design (not vulnerabilities)

- A server can withhold or delay transactions, refuse service, or return bad fee estimates. The user can
  change server.
- We assume that the Electrum server does not collude with a Lightning counterparty, and that it does not
  collude with a swap counterparty. An attack that needs the server to work together with either of them is
  not a vulnerability.
- Routing nodes learn what any Lightning routing scheme reveals to them.
- A hot wallet holds its keys in process memory.
- Optional third-party services the user turns on (a cosigner, a watchtower, sync) are trusted for
  availability.
- The payee's own description in an invoice or payment request is shown to the user. Showing it as plain
  text, as the payee's, is by design.

## Components

- Matter most: the Lightning implementation (channel state, HTLC handling, on-chain enforcement, onion
  processing, transport), swaps, wallet and keystore logic, building, signing and parsing transactions and
  PSBTs, key derivation and cryptography, wallet storage and encryption, the server client and chain
  verification, the daemon and its commands, parsing and resolving payment requests, and plugin loading.
  Also everything that decides what goes into a release binary: build scripts and Dockerfiles, dependency
  pins and the libraries built from source (`contrib/`), CI workflows (`.github/`), and the update checker.
- In scope but less important: the GUIs, except where they show what is about to be signed or show text
  from a remote party or a translator; hardware wallet integrations; other plugins.
- Out of scope: bugs in build tooling that do not let foreign code into a release, tests, vendored and
  third-party code in the tree (submodules other than `electrum/locale`, vendored packages), and bugs in
  dependencies unless Electrum uses them unsafely.

## How to exercise it

The OSS Scanner image has Electrum installed in editable mode at `/src`, plus `bitcoind`, `bitcoin-cli`
and `electrumx_server` on `PATH`. All of the below works offline.

- Unit tests: `python3 -m pytest tests`. The Lightning tests under `tests/` run several nodes in one process
  with mocked networking. They are the quickest way to reproduce a channel or HTLC bug.
- A wallet without a network: `./run_electrum --offline -D <dir> ...`.
- A local regtest network: `.github/workflows/regtest.yml` shows how CI starts `bitcoind` and ElectrumX and
  runs the regtest suite, and the scripts it calls show how to fund wallets, open channels, pay and
  force-close.
- To act as a malicious server, run one that speaks the Electrum protocol (newline-delimited JSON-RPC over
  TCP) and connect a regtest client to it only: `--regtest --oneserver --server 127.0.0.1:<port>:t`.
