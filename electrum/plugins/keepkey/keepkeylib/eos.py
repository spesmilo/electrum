import hashlib
import binascii
import struct
from datetime import datetime
from .tools import b58decode, b58encode, parse_path, int_to_big_endian
from . import messages_eos_pb2 as proto

def name_to_number(name):
    length = len(name)
    value = 0

    for i in range(0, 13):
        c = 0
        if i < length and i < 13:
            c = char_to_symbol(name[i])

        if i < 12:
            c &= 0x1f
            c <<= 64 - 5 * (i + 1)
        else:
            c &= 0x0f

        value |= c

    return value

def asset_to_number(asset):
    amount_str, symol_str = asset.split(' ')
    dot_pos = amount_str.find('.')

    # parse symbol
    if dot_pos != -1:
        precision_digit = len(amount_str) - dot_pos - 1
    else:
        precision_digit = 0

    sym = symbol_from_string(precision_digit, symol_str)

    # parse amount
    if dot_pos != -1:
        int_part = int(amount_str[:dot_pos])
        fract_part = int(amount_str[dot_pos+1:])
        if int_part < 0:
            fract_part *= -1
    else:
        int_part = int(amount_str)

    amount = int_part
    amount *= symbol_precision(sym)
    amount += fract_part

    return amount, sym

def char_to_symbol(c):
    if ord(c) >= ord('a') and ord(c) <= ord('z'):
        return (ord(c) - ord('a')) + 6
    if ord(c) >= ord('1') and ord(c) <= ord('5'):
        return (ord(c) - ord('1')) + 1
    return 0

def symbol_from_string(p, name):
    length = len(name)
    result = 0
    for i in range(0, length):
        result |= ord(name[i]) << (8 *(i+1))

    result |= p
    return result

def symbol_precision(sym):
    return pow(10, (sym & 0xff))

def public_key_to_buffer(pub_key):
    _t = 0
    if pub_key[:3] == 'EOS':
        pub_key = pub_key[3:]
        _t = 0
    elif pub_key[:7] == 'PUB_K1_':
        pub_key = pub_key[7:]
        _t = 0
    elif pub_key[:7] == 'PUB_R1_':
        pub_key = pub_key[7:]
        _t = 1

    return _t, b58decode(pub_key, None)[:-4]

def h160(public_key):
    md = hashlib.new('ripemd160')
    md.update(public_key)
    return md.digest()

def public_key_to_wif(pub_key, prefix):
    if len(pub_key) == 65:
        head = 0x03 if (pub_key[64] & 0x01) == 1 else 0x02
        compressed_pub_key = bytes([head]) + pub_key[1:33]
    elif len(pub_key) == 33:
        compressed_pub_key = pub_key
    else:
        raise Exception("invalid public key length")
    return prefix + b58encode(compressed_pub_key + h160(compressed_pub_key)[:4])

def encode_signature(prefix, v, r, s, keyType):
    sig = struct.pack("B", v) + r + s
    return prefix + b58encode(sig + h160(sig + keyType)[:4])

def parse_common(action):
    authorization = []
    for auth in action['authorization']:
        authorization.append(
            proto.EosPermissionLevel(
                actor=name_to_number(auth['actor']),
                permission=name_to_number(auth['permission'])
            )
        )

    return proto.EosActionCommon(
        account=name_to_number(action['account']),
        name=name_to_number(action['name']),
        authorization=authorization
    )

def parse_transfer(data):
    amount, symbol = asset_to_number(data['quantity'])

    return proto.EosActionTransfer(
        sender=name_to_number(data['from']),
        receiver=name_to_number(data['to']),
        memo=data['memo'],
        quantity=proto.EosAsset(
            amount=amount,
            symbol=symbol
        )
    )

def parse_vote_producer(data):
    producers = []
    for producer in data['producers']:
        producers.append(name_to_number(producer))

    return proto.EosActionVoteProducer(
        voter=name_to_number(data['account']),
        proxy=name_to_number(data['proxy']),
        producers=producers
    )

def parse_buy_ram(data):
    amount, symbol = asset_to_number(data['quant'])

    return proto.EosActionBuyRam(
        payer=name_to_number(data['payer']),
        receiver=name_to_number(data['receiver']),
        quantity=proto.EosAsset(
            amount=amount,
            symbol=symbol
        )
    )

def parse_buy_rambytes(data):
    return proto.EosActionBuyRamBytes(
        payer=name_to_number(data['payer']),
        receiver=name_to_number(data['receiver']),
        bytes=int(data['bytes'])
    )

def parse_sell_ram(data):
    return proto.EosActionSellRam(
        account=name_to_number(data['account']),
        bytes=int(data['bytes'])
    )

def parse_delegatebw(data):
    amount_net, symbol_net = asset_to_number(data['stake_net'])
    amount_cpu, symbol_cpu = asset_to_number(data['stake_cpu'])

    return proto.EosActionDelegate(
        sender=name_to_number(data['from']),
        receiver=name_to_number(data['receiver']),
        net_quantity=proto.EosAsset(
            amount=amount_net,
            symbol=symbol_net
        ),
        cpu_quantity=proto.EosAsset(
            amount=amount_cpu,
            symbol=symbol_cpu
        ),
        transfer=bool(data['transfer'])
    )

def parse_undelegatebw(data):
    amount_net, symbol_net = asset_to_number(data['unstake_net_quantity'])
    amount_cpu, symbol_cpu = asset_to_number(data['unstake_cpu_quantity'])

    return proto.EosActionUndelegate(
        sender=name_to_number(data['from']),
        receiver=name_to_number(data['receiver']),
        net_quantity=proto.EosAsset(
            amount=amount_net,
            symbol=symbol_net
        ),
        cpu_quantity=proto.EosAsset(
            amount=amount_cpu,
            symbol=symbol_cpu
        )
    )

def parse_refund(data):
    return proto.EosActionRefund(
        owner=name_to_number(data['owner'])
    )

def parse_updateauth(data):
    auth = parse_authorization(data['auth'])

    return proto.EosActionUpdateAuth(
        account=name_to_number(data['account']),
        permission=name_to_number(data['permission']),
        parent=name_to_number(data['parent']),
        auth=auth
    )

def parse_deleteauth(data):
    return proto.EosActionDeleteAuth(
        account=name_to_number(data['account']),
        permission=name_to_number(data['permission'])
    )

def parse_linkauth(data):
    return proto.EosActionLinkAuth(
        account=name_to_number(data['account']),
        code=name_to_number(data['code']),
        type=name_to_number(data['type']),
        requirement=name_to_number(data['requirement'])
    )

def parse_unlinkauth(data):
    return proto.EosActionUnlinkAuth(
        account=name_to_number(data['account']),
        code=name_to_number(data['code']),
        type=name_to_number(data['type'])
    )

def parse_authorization(data):
    keys = []
    for key in data['keys']:
        if 'key' in key:
            _t, _k = public_key_to_buffer(key['key'])

            keys.append(
                proto.EosAuthorizationKey(
                    type=_t,
                    key=_k,
                    weight=int(key['weight'])
                )
            )
        elif 'address_n' in key:
            address_n=parse_path(key['address_n'])

            keys.append(
                proto.EosAuthorizationKey(
                    type=1,
                    address_n=address_n,
                    weight=int(key['weight'])
                )
            )

    accounts = []
    for account in data['accounts']:
        accounts.append(
            proto.EosAuthorizationAccount(
                account=proto.EosPermissionLevel(
                    actor=name_to_number(account['permission']['actor']),
                    permission=name_to_number(account['permission']['permission'])
                ),
                weight=int(account['weight'])
            )
        )

    waits = []
    for wait in data['waits']:
        waits.append(
            proto.EosAuthorizationWait(
                wait_sec=int(wait['wait_sec']),
                weight=int(wait['weight'])
            )
        )

    return proto.EosAuthorization(
            threshold=int(data['threshold']),
            keys=keys,
            accounts=accounts,
            waits=waits,
        )

def parse_new_account(data):
    owner = parse_authorization(data['owner'])
    active = parse_authorization(data['active'])

    return proto.EosActionNewAccount(
            creator=name_to_number(data['creator']),
            name=name_to_number(data['name']),
            owner=owner,
            active=active
        )

def parse_unknown(data):
    res = []
    chunk_size = 256
    data = binascii.unhexlify(data)
    total = len(data)
    while 0 < len(data):
        res += [proto.EosActionUnknown(
            data_size=total,
            data_chunk=data[:chunk_size])]
        data=data[chunk_size:]
    return res

def parse_action(action):
    data = action['data']
    common = parse_common(action)

    if action['name'] == 'transfer':
        return proto.EosTxActionAck(common=common, transfer=parse_transfer(data))
    elif action['name'] == 'voteproducer':
        return proto.EosTxActionAck(common=common, vote_producer=parse_vote_producer(data))
    elif action['name'] == 'buyram':
        return proto.EosTxActionAck(common=common, buy_ram=parse_buy_ram(data))
    elif action['name'] == 'buyrambytes':
        return proto.EosTxActionAck(common=common, buy_ram_bytes=parse_buy_rambytes(data))
    elif action['name'] == 'sellram':
        return proto.EosTxActionAck(common=common, sell_ram=parse_sell_ram(data))
    elif action['name'] == 'delegatebw':
        return proto.EosTxActionAck(common=common, delegate=parse_delegatebw(data))
    elif action['name'] == 'undelegatebw':
        return proto.EosTxActionAck(common=common, undelegate=parse_undelegatebw(data))
    elif action['name'] == 'refund':
        return proto.EosTxActionAck(common=common, refund=parse_refund(data))
    elif action['name'] == 'updateauth':
        return proto.EosTxActionAck(common=common, update_auth=parse_updateauth(data))
    elif action['name'] == 'deleteauth':
        return proto.EosTxActionAck(common=common, delete_auth=parse_deleteauth(data))
    elif action['name'] == 'linkauth':
        return proto.EosTxActionAck(common=common, link_auth=parse_linkauth(data))
    elif action['name'] == 'unlinkauth':
        return proto.EosTxActionAck(common=common, unlink_auth=parse_unlinkauth(data))
    elif action['name'] == 'newaccount':
        return proto.EosTxActionAck(common=common, new_account=parse_new_account(data))
    else:
        return [proto.EosTxActionAck(common=common, unknown=u) for u in parse_unknown(data)]

def parse_transaction_json(json):
    tx = type('Transaction', (object,), {})()
    tx.chain_id = binascii.unhexlify(json['chain_id'])

    body = json['transaction']

    expiration = int((datetime.strptime(body['expiration'], '%Y-%m-%dT%H:%M:%S') - datetime(1970, 1, 1)).total_seconds())
    tx.expiration = expiration
    tx.ref_block_num = int(body['ref_block_num'])
    tx.ref_block_prefix = int(body['ref_block_prefix'])
    tx.net_usage_words = int(body['max_net_usage_words'])
    tx.max_cpu_usage_ms = int(body['max_cpu_usage_ms'])
    tx.delay_sec = int(body['delay_sec'])

    tx.actions = body['actions']

    tx.num_actions = len(tx.actions)

    return tx

