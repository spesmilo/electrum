from electrum.i18n import _
from electrum.commands import plugin_command
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .labels import LabelsPlugin
    from electrum.commands import Commands


fullname = _('LabelSync')
description = ' '.join([
    _("Save your wallet labels on a remote server, and synchronize them across multiple devices where you use Electrum."),
    _("Labels, transactions IDs and addresses are encrypted before they are sent to the remote server.")
])
available_for = ['qt', 'qml', 'cmdline']

plugin_name = "labels"

@plugin_command('w', plugin_name)
async def push(self: 'Commands', plugin: 'LabelsPlugin' = None, wallet=None) -> int:
    """ push labels to server """
    return await plugin.push_thread(wallet)


@plugin_command('w', plugin_name)
async def pull(self: 'Commands', plugin: 'LabelsPlugin' = None, wallet=None, force=False) -> int:
    """ pull labels from server """
    return await plugin.pull_thread(wallet, force=force)
