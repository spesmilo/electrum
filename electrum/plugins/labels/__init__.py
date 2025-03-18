from electrum.commands import plugin_command
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .labels import LabelsPlugin
    from electrum.commands import Commands

plugin_name = "labels"

@plugin_command('w', plugin_name)
async def push(self: 'Commands', plugin: 'LabelsPlugin' = None, wallet=None) -> int:
    """ push labels to server """
    return await plugin.push_thread(wallet)


@plugin_command('w', plugin_name)
async def pull(self: 'Commands', plugin: 'LabelsPlugin' = None, wallet=None, force=False) -> int:
    """
    pull missing labels from server

    arg:bool:force:pull all labels
    """
    return await plugin.pull_thread(wallet, force=force)
