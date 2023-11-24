from electrum.i18n import _


def to_rtf(msg):
    return '\n'.join(['<p>' + x + '</p>' for x in msg.split('\n\n')])


MSG_COOPERATIVE_CLOSE = _(
"""Your node will negotiate the transaction fee with the remote node. This method of closing the channel usually results in the lowest fees."""
)

MSG_REQUEST_FORCE_CLOSE = _(
"""If you request a force-close, your node will pretend that it has lost its data and ask the remote node to broadcast their latest state. Doing so from time to time helps make sure that nodes are honest, because your node can punish them if they broadcast a revoked state."""
)

MSG_CREATED_NON_RECOVERABLE_CHANNEL = _(
"""The channel you created is not recoverable from seed.
To prevent fund losses, please save this backup on another device.
It may be imported in another Electrum wallet with the same seed."""
)

MSG_LIGHTNING_EXPERIMENTAL_WARNING = _(
"""Lightning support in Electrum is experimental. Do not put large amounts in lightning channels."""
)

MSG_LIGHTNING_SCB_WARNING = _(
"""Electrum uses static channel backups. If you lose your wallet file, you will need to request your channel to be force-closed by the remote peer in order to recover your funds. This assumes that the remote peer is reachable, and has not lost its own data."""
)

MSG_LIGHTNING_WARNING = MSG_LIGHTNING_EXPERIMENTAL_WARNING + "\n\n" + MSG_LIGHTNING_SCB_WARNING

MGS_CONFLICTING_BACKUP_INSTANCE = _(
"""Another instance of this wallet (same seed) has an open channel with the same remote node. If you create this channel, you will not be able to use both wallets at the same time.

Are you sure?"""
)


MSG_CAPITAL_GAINS = _(
"""This summary covers only on-chain transactions (no lightning!). Capital gains are computed by attaching an acquisition price to each UTXO in the wallet, and uses the order of blockchain events (not FIFO)."""
)

MSG_NON_TRAMPOLINE_CHANNEL_FROZEN_WITHOUT_GOSSIP = _(
"""This channel is with a non-trampoline node; it cannot be used if trampoline is enabled.
If you want to keep using this channel, you need to disable trampoline routing in your preferences."""
)

MSG_FREEZE_ADDRESS = _("When you freeze an address, the funds in that address will not be used for sending bitcoins.")
MSG_FREEZE_COIN = _("When you freeze a coin, it will not be used for sending bitcoins.")
