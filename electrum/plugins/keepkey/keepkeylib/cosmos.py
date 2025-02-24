import base64
import schema
import copy

tx_schema = schema.Schema({
    "type": "auth/StdTx",
    "value": schema.Schema({
        "fee": schema.Schema({
            "amount": schema.Schema([{
                "denom": "uatom",
                "amount": unicode
            }]),
            "gas": unicode
        }),
        # NOTE: this needs to be 'msgs' when signing, but 'msg' when broadcasting.
        "msg": schema.Schema([{
            "type": "cosmos-sdk/MsgSend",
            "value": schema.Schema({
                "from_address": unicode,
                "to_address": unicode,
                "amount": schema.Schema([{
                    "denom": "uatom",
                    "amount": unicode
                }])
            })
        }]),
        schema.Optional("signatures"): None,
        "memo": unicode
    })
})

def cosmos_parse_tx(tx):
    validated = tx_schema.validate(tx)

    stdtx = validated['value']

    return {
        'fee': stdtx['fee']['amount'][0]['amount'],
        'gas': stdtx['fee']['gas'],
        'msgs': stdtx['msg'],
        'memo': stdtx['memo']
    }


def cosmos_append_sig(tx, public_key, signature):
    tx = copy.deepcopy(tx)

    tx['value']['signatures'] = [{
        "pub_key": {
            "type": "tendermint/PubKeySecp256k1",
            "value": base64.b64encode(public_key)
        },
        "signature": base64.b64encode(signature)
    }]

    return tx