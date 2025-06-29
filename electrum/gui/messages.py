from electrum.i18n import _
from electrum.submarine_swaps import MIN_FINAL_CLTV_DELTA_FOR_CLIENT


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

MSG_LIGHTNING_WARNING = _(
"""Electrum uses static channel backups. If you lose your wallet file, you will need to request your channel to be force-closed by the remote peer in order to recover your funds. This assumes that the remote peer is reachable, and has not lost its own data."""
)

MSG_THIRD_PARTY_PLUGIN_WARNING = ' '.join([
    '<b>' + _('Warning: Third-party plugins have access to your wallet!') + '</b>',
    '<br/><br/>',
    _('Installing this plugin will grant third-party software access to your wallet. You must trust the plugin not to be malicious.'),
    _('You should at minimum check who the author of the plugin is, and be careful of imposters.'),
    '<br/><br/>',
    _('Third-party plugins are not endorsed by Electrum.'),
    _('Electrum will not be responsible in case of theft, loss of funds or privacy that might result from third-party plugins.'),
    '<br/><br/>',
    _('To install this plugin, please enter your plugin authorization password') + ':'
])

MSG_CONFLICTING_BACKUP_INSTANCE = _(
"""Another instance of this wallet (same seed) has an open channel with the same remote node. If you create this channel, you will not be able to use both wallets at the same time.

Are you sure?"""
)

MSG_LN_EXPLAIN_SCB_BACKUPS = "".join([
    _("Channel backups can be imported in another instance of the same wallet."), " ",
    _("In the Electrum mobile app, use the 'Send' button to scan this QR code."), " ",
    "\n\n",
    _("Please note that channel backups cannot be used to restore your channels."), " ",
    _("If you lose your wallet file, the only thing you can do with a backup is to request your channel to be closed, so that your funds will be sent on-chain."),
])

MSG_CAPITAL_GAINS = _(
"""This summary covers only on-chain transactions (no lightning!). Capital gains are computed by attaching an acquisition price to each UTXO in the wallet, and uses the order of blockchain events (not FIFO)."""
)

MSG_NON_TRAMPOLINE_CHANNEL_FROZEN_WITHOUT_GOSSIP = _(
"""This channel is with a non-trampoline node; it cannot be used if trampoline is enabled.
If you want to keep using this channel, you need to disable trampoline routing in your preferences."""
)

MSG_FREEZE_ADDRESS = _("When you freeze an address, the funds in that address will not be used for sending bitcoins.")
MSG_FREEZE_COIN = _("When you freeze a coin, it will not be used for sending bitcoins.")

MSG_FORWARD_SWAP_FUNDING_MEMPOOL = (
    _('Your funding transaction has been broadcast.') + " " +
    _("Please remain online until the funding transaction is confirmed.") + "\n\n" +
    _('The swap will be finalized once your transaction is confirmed.') + " " +
    _("After the funding transaction is mined, the server will reveal the preimage needed to "
      "fulfill the pending received lightning HTLCs. The HTLCs expire in {} blocks. "
      "You will need to be online after the funding transaction is confirmed but before the HTLCs expire, "
      "to claim your money. If you go offline for several days while the swap is pending, "
      "you risk losing the swap amount!").format(MIN_FINAL_CLTV_DELTA_FOR_CLIENT)
)

MSG_REVERSE_SWAP_FUNDING_MEMPOOL = (
    _('The funding transaction has been detected.') + " " +
    _('Your claiming transaction will be broadcast when the funding transaction is confirmed.') + " " +
    _("If you go offline before broadcasting the claiming transaction and let the swap time out, "
      "you will not get back the already pre-paid mining fees.")
)

MSG_FORCE_CLOSE_WARNING = (
    _('You will need to come back online after the commitment transaction is confirmed, in order to broadcast second-stage htlc transactions.') + ' ' +
    _('If you remain offline for more than {} blocks, your channel counterparty will be able to sweep those funds.')
)

MSG_FORWARD_SWAP_WARNING = (
    _('You will need to come back online after the funding transaction is confirmed, in order to settle the swap.') + ' ' +
    _('If you remain offline for more than {} blocks, your channel will be force closed and you might lose the funds you sent in the swap.')
)

MSG_REVERSE_SWAP_WARNING = (
    _('You will need to come back online after the funding transaction is confirmed, in order to settle the swap.') + ' ' +
    _('If you remain offline for more than {} blocks, the swap will be cancelled and you will lose the prepaid mining fees.')
)

MSG_LN_UTXO_RESERVE = (
    _("You do not have enough on-chain funds to protect your Lightning channels.") + ' ' +
    _("You should have at least {} on-chain in order to be able to sweep channel outputs.")
)

# not to be translated
MSG_TERMS_OF_USE = (
"""1. Electrum is distributed under the MIT licence by Electrum Technologies GmbH. Most notably, this means that the Electrum software is provided as is, and that it comes without warranty.

2. We are neither a bank nor a financial service provider. In addition, we do not store user account data, and we are not an intermediary in the interaction between our software and the Bitcoin blockchain. Therefore, we do not have the possibility to freeze funds or to undo a fraudulent transaction.

3. We do not provide private user support. All issue resolutions are public, and take place on Github or public forums. If someone posing as 'Electrum support' proposes to help you via a private channel, this person is most likely an imposter trying to steal your bitcoins."""
)
TERMS_OF_USE_LATEST_VERSION : int = 1  # bump this if we want users re-prompted due to changes


MSG_CONNECTMODE_AUTOCONNECT = _('Auto-connect')
MSG_CONNECTMODE_MANUAL = _('Manual server selection')
MSG_CONNECTMODE_ONESERVER = _('Connect only to a single server')

MSG_CONNECTMODE_SERVER_HELP = _(
    "Electrum connects to a unique server in order to receive your transaction history. "
    "This server will learn your wallet addresses."
)
MSG_CONNECTMODE_NODES_HELP = _(
    "In addition to your history server, Electrum will try to maintain connections with ~10 extra servers, in order to download block headers and find out the longest blockchain. "
    "These servers are only used for block header notifications and fee estimates; they do not learn your wallet addresses. "
    "Getting block headers from multiple sources is useful to detect lagging servers and forks. "
    "Fork detection is security-critical for determining number of confirmations."
)

MSG_CONNECTMODE_AUTOCONNECT_HELP = _(
    "Electrum will always use a history server that is on the longest blockchain. "
    "If your current server is unresponsive or lagging, Electrum will switch to another server."
)

MSG_CONNECTMODE_MANUAL_HELP = _(
    "Electrum will stay with the server you selected. It will warn you if your server is lagging."
)

MSG_CONNECTMODE_ONESERVER_HELP = _(
    "Electrum will stay with the server you selected, and it will not connect to additional nodes. "
    "This will disable fork detection. "
    "This mode is only intended for connecting to your own fully trusted server. "
    "Using this option on a public server is a security risk and is discouraged."
)
