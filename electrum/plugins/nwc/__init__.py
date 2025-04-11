from electrum.commands import plugin_command
from typing import TYPE_CHECKING
from electrum.simple_config import SimpleConfig, ConfigVar

if TYPE_CHECKING:
    from .nwcserver import NWCServerPlugin
    from electrum.commands import Commands

plugin_name = "nwc"

# Most NWC clients only use the first relay encoded in the connection string.
# This relay will be used as the first relay in the connection string.
SimpleConfig.NWC_RELAY = ConfigVar(
    key='plugins.nwc.relay',
    default='wss://relay.getalby.com/v1',
    type_=str,
    plugin=plugin_name
)


@plugin_command('', plugin_name)
async def add_connection(
    self: 'Commands',
    name: str,
    daily_limit_sat=None,
    valid_for_sec=None,
    plugin: 'NWCServerPlugin' = None) -> str:
    """
    Create a new NWC connection string.

    arg:str:name:name for the connection (e.g. nostr client name)
    arg:int:daily_limit_sat:optional daily spending limit in satoshis
    arg:int:valid_for_sec:optional lifetime of the connection string in seconds
    """
    connection_string: str = plugin.create_connection(name, daily_limit_sat, valid_for_sec)
    return connection_string

@plugin_command('', plugin_name)
async def remove_connection(self: 'Commands', name: str, plugin=None) -> str:
    """
    Remove a connection by name.
    arg:str:name:connection name, use list_connections to see all connections
    """
    plugin.remove_connection(name)
    return f"removed connection {name}"

@plugin_command('', plugin_name)
async def list_connections(self: 'Commands', plugin=None) -> dict:
    """
    List all connections by name.
    """
    connections: dict = plugin.list_connections()
    return connections
