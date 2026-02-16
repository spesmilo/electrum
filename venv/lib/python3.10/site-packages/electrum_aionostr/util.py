from .key import PublicKey, PrivateKey, bech32

NIP19_PREFIXES = ('npub', 'nsec', 'note', 'nprofile', 'nevent', 'nrelay', 'nostr:', 'naddr')


def from_nip19(nip19string: str):
    """
    Decode nip-19 formatted string into:
    private key, public key, event id or profile public key
    """
    hrp, data, spec = bech32.bech32_decode(nip19string)
    data = bech32.convertbits(data, 5, 8)
    retval = {
        'object': None,
        'type': hrp,
        'relays': None,
    }
    if hrp == 'npub':
        retval['object'] = PublicKey(bytes(data[:-1]))
    elif hrp == 'nsec':
        retval['object'] = PrivateKey(bytes(data[:-1]))
    elif hrp == 'note':
        retval['object'] = bytes(data[:-1]).hex()
    elif hrp in ('nevent', 'nprofile', 'nrelay', 'naddr'):
        tlv = {0: [], 1: [], 2: [], 3: []}
        while data:
            t = data[0]
            try:
                l = data[1]
            except IndexError:
                break
            v = data[2:2+l]
            data = data[2+l:]
            if not v:
                continue
            tlv[t].append(v)
        if tlv[0]:
            if hrp not in ('nrelay', 'naddr'):
                key_or_id = bytes(tlv[0][0]).hex()
            else:
                key_or_id = bytes(tlv[0][0]).decode()
        else:
            key_or_id = ''
        relays = []
        for relay in tlv[1]:
            relays.append(bytes(relay).decode('utf8'))
        if tlv[2]:
            retval['author'] = bytes(tlv[2][0]).hex()
        if tlv[3]:
            retval['kind'] = int.from_bytes(bytes(tlv[3][0]), 'big')
        retval['object'] = key_or_id
        retval['relays'] = relays
    return retval


def to_nip19(ntype: str, payload: str, relays=None, author=None, kind=None):
    """
    Encode object as nip-19 compatible string
    """
    if ntype in ('npub', 'nsec', 'note'):
        data = bytes.fromhex(payload)
    elif ntype in ('nprofile', 'nevent', 'nrelay', 'naddr'):
        data = bytearray()
        if ntype == 'nrelay':
            encoded = payload.encode()
            data.append(0)
            data.append(len(encoded))
            data.extend(encoded)
        elif ntype == 'naddr':
            encoded = payload.encode()
            data.append(0)
            data.append(len(encoded))
            data.extend(encoded)
            if author:
                author_encoded = bytes.fromhex(author)
                data.append(2)
                data.append(len(author_encoded))
                data.extend(author_encoded)
            if kind:
                kind_bytes = kind.to_bytes(4, 'big')
                data.append(3)
                data.append(len(kind_bytes))
                data.extend(kind_bytes)
        else:
            # payload is event id
            event_id = bytes.fromhex(payload)
            data.append(0)
            data.append(len(event_id))
            data.extend(event_id)
        if relays:
            for r in relays:
                r = r.encode()
                data.append(1)
                data.append(len(r))
                data.extend(r)
    else:
        data = payload.encode()
    converted_bits = bech32.convertbits(data, 8, 5)
    return bech32.bech32_encode(ntype, converted_bits, bech32.Encoding.BECH32)

def normalize_url(url: str) -> str:
    stripped_url = url.strip().rstrip('/').lower()
    if not stripped_url.startswith(('ws://', 'wss://')):
        stripped_url = 'wss://' + stripped_url
    return stripped_url
