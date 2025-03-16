from electrum.commands import plugin_command
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .labels import LabelsPlugin
    from electrum.commands import Commands

plugin_name = "labels"

@plugin_command('w', plugin_name)
async def push(self: 'Commands', wallet=None) -> int:
    """ push labels to server """
    plugin: 'LabelsPlugin' = self.daemon._plugins.get_plugin(plugin_name)
    return await plugin.push_thread(wallet)


@plugin_command('w', plugin_name)
async def pull(self: 'Commands', wallet=None) -> int:
    """ pull labels from server """
    assert wallet is not None
    plugin: 'LabelsPlugin' = self.daemon._plugins.get_plugin(plugin_name)
    return await plugin.pull_thread(wallet, force=False)
