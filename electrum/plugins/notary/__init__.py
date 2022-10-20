from electrum.simple_config import ConfigVar, SimpleConfig
from electrum.commands import plugin_command

from typing import TYPE_CHECKING, List
if TYPE_CHECKING:
    from electrum.commands import Commands
    from electrum.wallet import Abstract_Wallet


plugin_name = 'notary'

SimpleConfig.NOTARY_SERVER_PORT = ConfigVar('plugins.notary.server_port', default=5455, type_=int, plugin=plugin_name)


@plugin_command('wl', plugin_name)
async def notarize(self: 'Commands', event_id:str, event_pubkey: str, log_fee: int, wallet: 'Abstract_Wallet' = None, plugin = None) -> List[dict]:
    """ add request 
    arg:str:event_id:nostr event id
    arg:str:event_pubkey:nostr event pubkey
    arg:int:log_fee:logarithm (base 2) of the fee, in sats. 0 means 1 sat
    """
    r = plugin.notary.add_request(event_id, event_pubkey, log_fee)
    return r['lightning_invoice']

@plugin_command('wl', plugin_name)
async def get_proof(self: 'Commands', rhash: str, wallet: 'Abstract_Wallet' = None, plugin = None) -> List[dict]:
    """ request notarization proof 
    arg:str:rhash:nostr event id
    """
    return plugin.notary.get_proof(rhash)
