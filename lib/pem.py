#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
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


# This module uses code from TLSLlite
# TLSLite Author: Trevor Perrin)


import binascii

from x509 import ASN1_Node, bytestr_to_int, decode_OID


def a2b_base64(s):
    try:
        b = bytearray(binascii.a2b_base64(s))
    except Exception as e:
        raise SyntaxError("base64 error: %s" % e)
    return b

def b2a_base64(b):
    return binascii.b2a_base64(b)


def dePem(s, name):
    """Decode a PEM string into a bytearray of its payload.
    
    The input must contain an appropriate PEM prefix and postfix
    based on the input name string, e.g. for name="CERTIFICATE":

    -----BEGIN CERTIFICATE-----
    MIIBXDCCAUSgAwIBAgIBADANBgkqhkiG9w0BAQUFADAPMQ0wCwYDVQQDEwRUQUNL
    ...
    KoZIhvcNAQEFBQADAwA5kw==
    -----END CERTIFICATE-----    

    The first such PEM block in the input will be found, and its
    payload will be base64 decoded and returned.
    """
    prefix  = "-----BEGIN %s-----" % name
    postfix = "-----END %s-----" % name    
    start = s.find(prefix)
    if start == -1:
        raise SyntaxError("Missing PEM prefix")
    end = s.find(postfix, start+len(prefix))
    if end == -1:
        raise SyntaxError("Missing PEM postfix")
    s = s[start+len("-----BEGIN %s-----" % name) : end]
    retBytes = a2b_base64(s) # May raise SyntaxError
    return retBytes

def dePemList(s, name):
    """Decode a sequence of PEM blocks into a list of bytearrays.

    The input must contain any number of PEM blocks, each with the appropriate
    PEM prefix and postfix based on the input name string, e.g. for
    name="TACK BREAK SIG".  Arbitrary text can appear between and before and
    after the PEM blocks.  For example:

    " Created by TACK.py 0.9.3 Created at 2012-02-01T00:30:10Z -----BEGIN TACK
    BREAK SIG-----
    ATKhrz5C6JHJW8BF5fLVrnQss6JnWVyEaC0p89LNhKPswvcC9/s6+vWLd9snYTUv
    YMEBdw69PUP8JB4AdqA3K6Ap0Fgd9SSTOECeAKOUAym8zcYaXUwpk0+WuPYa7Zmm
    SkbOlK4ywqt+amhWbg9txSGUwFO5tWUHT3QrnRlE/e3PeNFXLx5Bckg= -----END TACK
    BREAK SIG----- Created by TACK.py 0.9.3 Created at 2012-02-01T00:30:11Z
    -----BEGIN TACK BREAK SIG-----
    ATKhrz5C6JHJW8BF5fLVrnQss6JnWVyEaC0p89LNhKPswvcC9/s6+vWLd9snYTUv
    YMEBdw69PUP8JB4AdqA3K6BVCWfcjN36lx6JwxmZQncS6sww7DecFO/qjSePCxwM
    +kdDqX/9/183nmjx6bf0ewhPXkA0nVXsDYZaydN8rJU1GaMlnjcIYxY= -----END TACK
    BREAK SIG----- "
    
    All such PEM blocks will be found, decoded, and return in an ordered list
    of bytearrays, which may have zero elements if not PEM blocks are found.
     """
    bList = []
    prefix  = "-----BEGIN %s-----" % name
    postfix = "-----END %s-----" % name
    while 1:
        start = s.find(prefix)
        if start == -1:
            return bList
        end = s.find(postfix, start+len(prefix))
        if end == -1:
            raise SyntaxError("Missing PEM postfix")
        s2 = s[start+len(prefix) : end]
        retBytes = a2b_base64(s2) # May raise SyntaxError
        bList.append(retBytes)
        s = s[end+len(postfix) : ]

def pem(b, name):
    """Encode a payload bytearray into a PEM string.
    
    The input will be base64 encoded, then wrapped in a PEM prefix/postfix
    based on the name string, e.g. for name="CERTIFICATE":
    
    -----BEGIN CERTIFICATE-----
    MIIBXDCCAUSgAwIBAgIBADANBgkqhkiG9w0BAQUFADAPMQ0wCwYDVQQDEwRUQUNL
    ...
    KoZIhvcNAQEFBQADAwA5kw==
    -----END CERTIFICATE-----    
    """
    s1 = b2a_base64(b)[:-1] # remove terminating \n
    s2 = ""
    while s1:
        s2 += s1[:64] + "\n"
        s1 = s1[64:]
    s = ("-----BEGIN %s-----\n" % name) + s2 + \
        ("-----END %s-----\n" % name)     
    return s

def pemSniff(inStr, name):
    searchStr = "-----BEGIN %s-----" % name
    return searchStr in inStr


def parse_private_key(s):
    """Parse a string containing a PEM-encoded <privateKey>."""
    if pemSniff(s, "PRIVATE KEY"):
        bytes = dePem(s, "PRIVATE KEY")
        return _parsePKCS8(bytes)
    elif pemSniff(s, "RSA PRIVATE KEY"):
        bytes = dePem(s, "RSA PRIVATE KEY")
        return _parseSSLeay(bytes)
    else:
        raise SyntaxError("Not a PEM private key file")


def _parsePKCS8(bytes):
    s = ASN1_Node(str(bytes))
    root = s.root()
    version_node = s.first_child(root)
    version = bytestr_to_int(s.get_value_of_type(version_node, 'INTEGER'))
    if version != 0:
        raise SyntaxError("Unrecognized PKCS8 version")
    rsaOID_node = s.next_node(version_node)
    ii = s.first_child(rsaOID_node)
    rsaOID = decode_OID(s.get_value_of_type(ii, 'OBJECT IDENTIFIER'))
    if rsaOID != '1.2.840.113549.1.1.1':
        raise SyntaxError("Unrecognized AlgorithmIdentifier")
    privkey_node = s.next_node(rsaOID_node)
    value = s.get_value_of_type(privkey_node, 'OCTET STRING')
    return _parseASN1PrivateKey(value)


def _parseSSLeay(bytes):
    return _parseASN1PrivateKey(ASN1_Node(str(bytes)))


def bytesToNumber(s):
    return int(binascii.hexlify(s), 16)


def _parseASN1PrivateKey(s):
    s = ASN1_Node(s)
    root = s.root()
    version_node = s.first_child(root)
    version = bytestr_to_int(s.get_value_of_type(version_node, 'INTEGER'))
    if version != 0:
        raise SyntaxError("Unrecognized RSAPrivateKey version")
    n = s.next_node(version_node)
    e = s.next_node(n)
    d = s.next_node(e)
    p = s.next_node(d)
    q = s.next_node(p)
    dP = s.next_node(q)
    dQ = s.next_node(dP)
    qInv = s.next_node(dQ)
    return map(lambda x: bytesToNumber(s.get_value_of_type(x, 'INTEGER')), [n, e, d, p, q, dP, dQ, qInv])

