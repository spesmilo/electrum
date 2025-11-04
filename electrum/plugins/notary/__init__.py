from electrum.simple_config import ConfigVar, SimpleConfig
from electrum.commands import plugin_command

from typing import TYPE_CHECKING, List
if TYPE_CHECKING:
    from electrum.commands import Commands
    from electrum.wallet import Abstract_Wallet


plugin_name = 'notary'

SimpleConfig.NOTARY_SERVER_PORT = ConfigVar('plugins.notary.server_port', default=5455, type_=int, plugin=plugin_name)
SimpleConfig.NOTARY_FEERATE = ConfigVar('plugins.notary.feerate', default=1000, type_=int, plugin=plugin_name)
SimpleConfig.NOTARY_CSV_DELAY = ConfigVar('plugins.notary.csv_delay', default=144, type_=int, plugin=plugin_name)


@plugin_command('wl', plugin_name)
async def add_request(self: 'Commands', event_id:str, value: int, pubkey: str = None, signature: str = None, wallet: 'Abstract_Wallet' = None, plugin = None) -> List[dict]:
    """Request notarization. This returns a lightning invoice.
    arg:str:event_id:nostr event id (hexadecimal)
    arg:int:value:amount to be burnt, in satoshis.
    arg:str:pubkey:upvoter pubkey
    arg:str:signature:upvoter signature
    """
    return plugin.notary.add_request(event_id, value, pubkey=pubkey, signature=signature)

@plugin_command('wl', plugin_name)
async def get_proof(self: 'Commands', rhash: str, wallet: 'Abstract_Wallet' = None, plugin = None) -> List[dict]:
    """Request proof of burn
    arg:str:rhash:nostr event id
    """
    p = plugin.notary.get_proof(rhash)
    await plugin.notary.verify_proof(p)
    return p

@plugin_command('wl', plugin_name)
async def verify_proof(self: 'Commands', proof: str, wallet: 'Abstract_Wallet' = None, plugin = None) -> List[dict]:
    """Verify proof of burn
    arg:str:proof:proof
    """
    return await plugin.notary.verify_proof(proof)

@plugin_command('wl', plugin_name)
async def sweep(self: 'Commands', txid: str, wallet: 'Abstract_Wallet' = None, plugin = None) -> List[dict]:
    """Sweep funds that have been burnt
    arg:str:txid:txid of the notarization transaction
    """
    return await plugin.notary.sweep(txid)
