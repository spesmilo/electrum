# note: qt and kivy use different i18n methods

def to_rtf(msg):
    return '\n'.join(['<p>' + x + '</p>' for x in msg.split('\n\n')])

MSG_RECOVERABLE_CHANNELS = """
Add extra data to your channel funding transactions, so that a static backup can be recovered from your seed.

Note that static backups only allow you to request a force-close with the remote node. This assumes that the remote node is still online, did not lose its data, and accepts to force close the channel.

If this is enabled, other nodes cannot open a channel to you. Channel recovery data is encrypted, so that only your wallet can decrypt it. However, blockchain analysis will be able to tell that the transaction was probably created by Electrum.
"""

MSG_REQUEST_FORCE_CLOSE = """
You may choose to initiate a cooperative close, or request the remote peer to force close the channel.

If you request a force-close, your node will pretend that it has lost its data and ask the remote node to broadcast their latest state. Doing so from time to time helps make sure that nodes are honest, because your node can punish them if they broadcast a revoked state."""

MSG_CREATED_NON_RECOVERABLE_CHANNEL = """
The channel you created is not recoverable from seed.
To prevent fund losses, please save this backup on another device.
It may be imported in another Electrum wallet with the same seed.
"""

MSG_LIGHTNING_WARNING = """
Electrum uses static channel backups. If you lose your wallet file, you will need to request your channel to be force-closed by the remote peer in order to recover your funds. This assumes that the remote peer is reachable, and has not lost its own data.
"""

MSG_HELP_TRAMPOLINE = """
Lightning payments require finding a path through the Lightning Network. You may use trampoline routing, or local routing (gossip).

Downloading the network gossip uses quite some bandwidth and storage, and is not recommended on mobile devices. If you use trampoline, you can only open channels with trampoline nodes.
"""

MGS_CONFLICTING_BACKUP_INSTANCE = """
Another instance of this wallet (same seed) has an open channel with the same remote node. If you create this channel, you will not be able to use both wallets at the same time.

Are you sure?
"""


MSG_CAPITAL_GAINS = """
This summary covers only on-chain transactions (no lightning!). Capital gains are computed by attaching an acquisition price to each UTXO in the wallet, and uses the order of blockchain events (not FIFO).
"""
