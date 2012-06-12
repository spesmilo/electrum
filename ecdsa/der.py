import binascii
import base64

class UnexpectedDER(Exception):
    pass

def encode_constructed(tag, value):
    return chr(0xa0+tag) + encode_length(len(value)) + value
def encode_integer(r):
    assert r >= 0 # can't support negative numbers yet
    h = "%x" % r
    if len(h)%2:
        h = "0" + h
    s = binascii.unhexlify(h)
    if ord(s[0]) <= 0x7f:
        return "\x02" + chr(len(s)) + s
    else:
        # DER integers are two's complement, so if the first byte is
        # 0x80-0xff then we need an extra 0x00 byte to prevent it from
        # looking negative.
        return "\x02" + chr(len(s)+1) + "\x00" + s

def encode_bitstring(s):
    return "\x03" + encode_length(len(s)) + s
def encode_octet_string(s):
    return "\x04" + encode_length(len(s)) + s
def encode_oid(first, second, *pieces):
    assert first <= 2
    assert second <= 39
    encoded_pieces = [chr(40*first+second)] + [encode_number(p)
                                               for p in pieces]
    body = "".join(encoded_pieces)
    return "\x06" + encode_length(len(body)) + body
def encode_sequence(*encoded_pieces):
    total_len = sum([len(p) for p in encoded_pieces])
    return "\x30" + encode_length(total_len) + "".join(encoded_pieces)
def encode_number(n):
    b128_digits = []
    while n:
        b128_digits.insert(0, (n & 0x7f) | 0x80)
        n = n >> 7
    if not b128_digits:
        b128_digits.append(0)
    b128_digits[-1] &= 0x7f
    return "".join([chr(d) for d in b128_digits])

def remove_constructed(string):
    s0 = ord(string[0])
    if (s0 & 0xe0) != 0xa0:
        raise UnexpectedDER("wanted constructed tag (0xa0-0xbf), got 0x%02x"
                            % s0)
    tag = s0 & 0x1f
    length, llen = read_length(string[1:])
    body = string[1+llen:1+llen+length]
    rest = string[1+llen+length:]
    return tag, body, rest

def remove_sequence(string):
    if not string.startswith("\x30"):
        raise UnexpectedDER("wanted sequence (0x30), got 0x%02x" %
                            ord(string[0]))
    length, lengthlength = read_length(string[1:])
    endseq = 1+lengthlength+length
    return string[1+lengthlength:endseq], string[endseq:]

def remove_octet_string(string):
    if not string.startswith("\x04"):
        raise UnexpectedDER("wanted octetstring (0x04), got 0x%02x" %
                            ord(string[0]))
    length, llen = read_length(string[1:])
    body = string[1+llen:1+llen+length]
    rest = string[1+llen+length:]
    return body, rest

def remove_object(string):
    if not string.startswith("\x06"):
        raise UnexpectedDER("wanted object (0x06), got 0x%02x" %
                            ord(string[0]))
    length, lengthlength = read_length(string[1:])
    body = string[1+lengthlength:1+lengthlength+length]
    rest = string[1+lengthlength+length:]
    numbers = []
    while body:
        n, ll = read_number(body)
        numbers.append(n)
        body = body[ll:]
    n0 = numbers.pop(0)
    first = n0//40
    second = n0-(40*first)
    numbers.insert(0, first)
    numbers.insert(1, second)
    return tuple(numbers), rest

def remove_integer(string):
    if not string.startswith("\x02"):
        raise UnexpectedDER("wanted integer (0x02), got 0x%02x" %
                            ord(string[0]))
    length, llen = read_length(string[1:])
    numberbytes = string[1+llen:1+llen+length]
    rest = string[1+llen+length:]
    assert ord(numberbytes[0]) < 0x80 # can't support negative numbers yet
    return int(binascii.hexlify(numberbytes), 16), rest

def read_number(string):
    number = 0
    llen = 0
    # base-128 big endian, with b7 set in all but the last byte
    while True:
        if llen > len(string):
            raise UnexpectedDER("ran out of length bytes")
        number = number << 7
        d = ord(string[llen])
        number += (d & 0x7f)
        llen += 1
        if not d & 0x80:
            break
    return number, llen

def encode_length(l):
    assert l >= 0
    if l < 0x80:
        return chr(l)
    s = "%x" % l
    if len(s)%2:
        s = "0"+s
    s = binascii.unhexlify(s)
    llen = len(s)
    return chr(0x80|llen) + s

def read_length(string):
    if not (ord(string[0]) & 0x80):
        # short form
        return (ord(string[0]) & 0x7f), 1
    # else long-form: b0&0x7f is number of additional base256 length bytes,
    # big-endian
    llen = ord(string[0]) & 0x7f
    if llen > len(string)-1:
        raise UnexpectedDER("ran out of length bytes")
    return int(binascii.hexlify(string[1:1+llen]), 16), 1+llen

def remove_bitstring(string):
    if not string.startswith("\x03"):
        raise UnexpectedDER("wanted bitstring (0x03), got 0x%02x" %
                            ord(string[0]))
    length, llen = read_length(string[1:])
    body = string[1+llen:1+llen+length]
    rest = string[1+llen+length:]
    return body, rest

# SEQUENCE([1, STRING(secexp), cont[0], OBJECT(curvename), cont[1], BINTSTRING)


# signatures: (from RFC3279)
#  ansi-X9-62  OBJECT IDENTIFIER ::= {
#       iso(1) member-body(2) us(840) 10045 }
#
#  id-ecSigType OBJECT IDENTIFIER  ::=  {
#       ansi-X9-62 signatures(4) }
#  ecdsa-with-SHA1  OBJECT IDENTIFIER ::= {
#       id-ecSigType 1 }
## so 1,2,840,10045,4,1
## so 0x42, .. ..

#  Ecdsa-Sig-Value  ::=  SEQUENCE  {
#       r     INTEGER,
#       s     INTEGER  }

# id-public-key-type OBJECT IDENTIFIER  ::= { ansi-X9.62 2 }
#
# id-ecPublicKey OBJECT IDENTIFIER ::= { id-publicKeyType 1 }

# I think the secp224r1 identifier is (t=06,l=05,v=2b81040021)
#  secp224r1 OBJECT IDENTIFIER ::= {
#  iso(1) identified-organization(3) certicom(132) curve(0) 33 }
# and the secp384r1 is (t=06,l=05,v=2b81040022)
#  secp384r1 OBJECT IDENTIFIER ::= {
#  iso(1) identified-organization(3) certicom(132) curve(0) 34 }

def unpem(pem):
    d = "".join([l.strip() for l in pem.split("\n")
                 if l and not l.startswith("-----")])
    return base64.b64decode(d)
def topem(der, name):
    b64 = base64.b64encode(der)
    lines = ["-----BEGIN %s-----\n" % name]
    lines.extend([b64[start:start+64]+"\n"
                  for start in range(0, len(b64), 64)])
    lines.append("-----END %s-----\n" % name)
    return "".join(lines)

