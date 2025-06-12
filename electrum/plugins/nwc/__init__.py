#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2025 The Electrum Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from typing import TYPE_CHECKING

from electrum.commands import plugin_command
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
    plugin: 'NWCServerPlugin' = None
) -> str:
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
