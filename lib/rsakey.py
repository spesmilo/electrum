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

# This module uses functions from TLSLite (public domain)
#
# TLSLite Authors: 
#   Trevor Perrin
#   Martin von Loewis - python 3 port
#   Yngve Pettersen (ported by Paul Sokolovsky) - TLS 1.2
#

"""Pure-Python RSA implementation."""


from __future__ import print_function
import os
import math
import base64
import binascii
import hashlib

from pem import *


def SHA1(x):
    return hashlib.sha1(x).digest()


# **************************************************************************
# PRNG Functions
# **************************************************************************

# Check that os.urandom works
import zlib
length = len(zlib.compress(os.urandom(1000)))
assert(length > 900)

def getRandomBytes(howMany):
    b = bytearray(os.urandom(howMany))
    assert(len(b) == howMany)
    return b

prngName = "os.urandom"


# **************************************************************************
# Converter Functions
# **************************************************************************

def bytesToNumber(b):
    total = 0
    multiplier = 1
    for count in range(len(b)-1, -1, -1):
        byte = b[count]
        total += multiplier * byte
        multiplier *= 256
    return total

def numberToByteArray(n, howManyBytes=None):
    """Convert an integer into a bytearray, zero-pad to howManyBytes.

    The returned bytearray may be smaller than howManyBytes, but will
    not be larger.  The returned bytearray will contain a big-endian
    encoding of the input integer (n).
    """    
    if howManyBytes == None:
        howManyBytes = numBytes(n)
    b = bytearray(howManyBytes)
    for count in range(howManyBytes-1, -1, -1):
        b[count] = int(n % 256)
        n >>= 8
    return b

def mpiToNumber(mpi): #mpi is an openssl-format bignum string
    if (ord(mpi[4]) & 0x80) !=0: #Make sure this is a positive number
        raise AssertionError()
    b = bytearray(mpi[4:])
    return bytesToNumber(b)

def numberToMPI(n):
    b = numberToByteArray(n)
    ext = 0
    #If the high-order bit is going to be set,
    #add an extra byte of zeros
    if (numBits(n) & 0x7)==0:
        ext = 1
    length = numBytes(n) + ext
    b = bytearray(4+ext) + b
    b[0] = (length >> 24) & 0xFF
    b[1] = (length >> 16) & 0xFF
    b[2] = (length >> 8) & 0xFF
    b[3] = length & 0xFF
    return bytes(b)


# **************************************************************************
# Misc. Utility Functions
# **************************************************************************

def numBits(n):
    if n==0:
        return 0
    s = "%x" % n
    return ((len(s)-1)*4) + \
    {'0':0, '1':1, '2':2, '3':2,
     '4':3, '5':3, '6':3, '7':3,
     '8':4, '9':4, 'a':4, 'b':4,
     'c':4, 'd':4, 'e':4, 'f':4,
     }[s[0]]
    return int(math.floor(math.log(n, 2))+1)

def numBytes(n):
    if n==0:
        return 0
    bits = numBits(n)
    return int(math.ceil(bits / 8.0))

# **************************************************************************
# Big Number Math
# **************************************************************************

def getRandomNumber(low, high):
    if low >= high:
        raise AssertionError()
    howManyBits = numBits(high)
    howManyBytes = numBytes(high)
    lastBits = howManyBits % 8
    while 1:
        bytes = getRandomBytes(howManyBytes)
        if lastBits:
            bytes[0] = bytes[0] % (1 << lastBits)
        n = bytesToNumber(bytes)
        if n >= low and n < high:
            return n

def gcd(a,b):
    a, b = max(a,b), min(a,b)
    while b:
        a, b = b, a % b
    return a

def lcm(a, b):
    return (a * b) // gcd(a, b)

#Returns inverse of a mod b, zero if none
#Uses Extended Euclidean Algorithm
def invMod(a, b):
    c, d = a, b
    uc, ud = 1, 0
    while c != 0:
        q = d // c
        c, d = d-(q*c), c
        uc, ud = ud - (q * uc), uc
    if d == 1:
        return ud % b
    return 0


def powMod(base, power, modulus):
    if power < 0:
        result = pow(base, power*-1, modulus)
        result = invMod(result, modulus)
        return result
    else:
        return pow(base, power, modulus)

#Pre-calculate a sieve of the ~100 primes < 1000:
def makeSieve(n):
    sieve = list(range(n))
    for count in range(2, int(math.sqrt(n))+1):
        if sieve[count] == 0:
            continue
        x = sieve[count] * 2
        while x < len(sieve):
            sieve[x] = 0
            x += sieve[count]
    sieve = [x for x in sieve[2:] if x]
    return sieve

sieve = makeSieve(1000)

def isPrime(n, iterations=5, display=False):
    #Trial division with sieve
    for x in sieve:
        if x >= n: return True
        if n % x == 0: return False
    #Passed trial division, proceed to Rabin-Miller
    #Rabin-Miller implemented per Ferguson & Schneier
    #Compute s, t for Rabin-Miller
    if display: print("*", end=' ')
    s, t = n-1, 0
    while s % 2 == 0:
        s, t = s//2, t+1
    #Repeat Rabin-Miller x times
    a = 2 #Use 2 as a base for first iteration speedup, per HAC
    for count in range(iterations):
        v = powMod(a, s, n)
        if v==1:
            continue
        i = 0
        while v != n-1:
            if i == t-1:
                return False
            else:
                v, i = powMod(v, 2, n), i+1
        a = getRandomNumber(2, n)
    return True

def getRandomPrime(bits, display=False):
    if bits < 10:
        raise AssertionError()
    #The 1.5 ensures the 2 MSBs are set
    #Thus, when used for p,q in RSA, n will have its MSB set
    #
    #Since 30 is lcm(2,3,5), we'll set our test numbers to
    #29 % 30 and keep them there
    low = ((2 ** (bits-1)) * 3) // 2
    high = 2 ** bits - 30
    p = getRandomNumber(low, high)
    p += 29 - (p % 30)
    while 1:
        if display: print(".", end=' ')
        p += 30
        if p >= high:
            p = getRandomNumber(low, high)
            p += 29 - (p % 30)
        if isPrime(p, display=display):
            return p

#Unused at the moment...
def getRandomSafePrime(bits, display=False):
    if bits < 10:
        raise AssertionError()
    #The 1.5 ensures the 2 MSBs are set
    #Thus, when used for p,q in RSA, n will have its MSB set
    #
    #Since 30 is lcm(2,3,5), we'll set our test numbers to
    #29 % 30 and keep them there
    low = (2 ** (bits-2)) * 3//2
    high = (2 ** (bits-1)) - 30
    q = getRandomNumber(low, high)
    q += 29 - (q % 30)
    while 1:
        if display: print(".", end=' ')
        q += 30
        if (q >= high):
            q = getRandomNumber(low, high)
            q += 29 - (q % 30)
        #Ideas from Tom Wu's SRP code
        #Do trial division on p and q before Rabin-Miller
        if isPrime(q, 0, display=display):
            p = (2 * q) + 1
            if isPrime(p, display=display):
                if isPrime(q, display=display):
                    return p


class RSAKey(object):

    def __init__(self, n=0, e=0, d=0, p=0, q=0, dP=0, dQ=0, qInv=0):
        if (n and not e) or (e and not n):
            raise AssertionError()
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.dP = dP
        self.dQ = dQ
        self.qInv = qInv
        self.blinder = 0
        self.unblinder = 0

    def __len__(self):
        """Return the length of this key in bits.

        @rtype: int
        """
        return numBits(self.n)

    def hasPrivateKey(self):
        return self.d != 0

    def hashAndSign(self, bytes):
        """Hash and sign the passed-in bytes.

        This requires the key to have a private component.  It performs
        a PKCS1-SHA1 signature on the passed-in data.

        @type bytes: str or L{bytearray} of unsigned bytes
        @param bytes: The value which will be hashed and signed.

        @rtype: L{bytearray} of unsigned bytes.
        @return: A PKCS1-SHA1 signature on the passed-in data.
        """
        hashBytes = SHA1(bytearray(bytes))
        prefixedHashBytes = self._addPKCS1SHA1Prefix(hashBytes)
        sigBytes = self.sign(prefixedHashBytes)
        return sigBytes

    def hashAndVerify(self, sigBytes, bytes):
        """Hash and verify the passed-in bytes with the signature.

        This verifies a PKCS1-SHA1 signature on the passed-in data.

        @type sigBytes: L{bytearray} of unsigned bytes
        @param sigBytes: A PKCS1-SHA1 signature.

        @type bytes: str or L{bytearray} of unsigned bytes
        @param bytes: The value which will be hashed and verified.

        @rtype: bool
        @return: Whether the signature matches the passed-in data.
        """
        hashBytes = SHA1(bytearray(bytes))
        
        # Try it with/without the embedded NULL
        prefixedHashBytes1 = self._addPKCS1SHA1Prefix(hashBytes, False)
        prefixedHashBytes2 = self._addPKCS1SHA1Prefix(hashBytes, True)
        result1 = self.verify(sigBytes, prefixedHashBytes1)
        result2 = self.verify(sigBytes, prefixedHashBytes2)
        return (result1 or result2)

    def sign(self, bytes):
        """Sign the passed-in bytes.

        This requires the key to have a private component.  It performs
        a PKCS1 signature on the passed-in data.

        @type bytes: L{bytearray} of unsigned bytes
        @param bytes: The value which will be signed.

        @rtype: L{bytearray} of unsigned bytes.
        @return: A PKCS1 signature on the passed-in data.
        """
        if not self.hasPrivateKey():
            raise AssertionError()
        paddedBytes = self._addPKCS1Padding(bytes, 1)
        m = bytesToNumber(paddedBytes)
        if m >= self.n:
            raise ValueError()
        c = self._rawPrivateKeyOp(m)
        sigBytes = numberToByteArray(c, numBytes(self.n))
        return sigBytes

    def verify(self, sigBytes, bytes):
        """Verify the passed-in bytes with the signature.

        This verifies a PKCS1 signature on the passed-in data.

        @type sigBytes: L{bytearray} of unsigned bytes
        @param sigBytes: A PKCS1 signature.

        @type bytes: L{bytearray} of unsigned bytes
        @param bytes: The value which will be verified.

        @rtype: bool
        @return: Whether the signature matches the passed-in data.
        """
        if len(sigBytes) != numBytes(self.n):
            return False
        paddedBytes = self._addPKCS1Padding(bytes, 1)
        c = bytesToNumber(sigBytes)
        if c >= self.n:
            return False
        m = self._rawPublicKeyOp(c)
        checkBytes = numberToByteArray(m, numBytes(self.n))
        return checkBytes == paddedBytes

    def encrypt(self, bytes):
        """Encrypt the passed-in bytes.

        This performs PKCS1 encryption of the passed-in data.

        @type bytes: L{bytearray} of unsigned bytes
        @param bytes: The value which will be encrypted.

        @rtype: L{bytearray} of unsigned bytes.
        @return: A PKCS1 encryption of the passed-in data.
        """
        paddedBytes = self._addPKCS1Padding(bytes, 2)
        m = bytesToNumber(paddedBytes)
        if m >= self.n:
            raise ValueError()
        c = self._rawPublicKeyOp(m)
        encBytes = numberToByteArray(c, numBytes(self.n))
        return encBytes

    def decrypt(self, encBytes):
        """Decrypt the passed-in bytes.

        This requires the key to have a private component.  It performs
        PKCS1 decryption of the passed-in data.

        @type encBytes: L{bytearray} of unsigned bytes
        @param encBytes: The value which will be decrypted.

        @rtype: L{bytearray} of unsigned bytes or None.
        @return: A PKCS1 decryption of the passed-in data or None if
        the data is not properly formatted.
        """
        if not self.hasPrivateKey():
            raise AssertionError()
        if len(encBytes) != numBytes(self.n):
            return None
        c = bytesToNumber(encBytes)
        if c >= self.n:
            return None
        m = self._rawPrivateKeyOp(c)
        decBytes = numberToByteArray(m, numBytes(self.n))
        #Check first two bytes
        if decBytes[0] != 0 or decBytes[1] != 2:
            return None
        #Scan through for zero separator
        for x in range(1, len(decBytes)-1):
            if decBytes[x]== 0:
                break
        else:
            return None
        return decBytes[x+1:] #Return everything after the separator




    # **************************************************************************
    # Helper Functions for RSA Keys
    # **************************************************************************

    def _addPKCS1SHA1Prefix(self, bytes, withNULL=True):
        # There is a long history of confusion over whether the SHA1 
        # algorithmIdentifier should be encoded with a NULL parameter or 
        # with the parameter omitted.  While the original intention was 
        # apparently to omit it, many toolkits went the other way.  TLS 1.2
        # specifies the NULL should be included, and this behavior is also
        # mandated in recent versions of PKCS #1, and is what tlslite has
        # always implemented.  Anyways, verification code should probably 
        # accept both.  However, nothing uses this code yet, so this is 
        # all fairly moot.
        if not withNULL:
            prefixBytes = bytearray(\
            [0x30,0x1f,0x30,0x07,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x04,0x14])            
        else:
            prefixBytes = bytearray(\
            [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14])            
        prefixedBytes = prefixBytes + bytes
        return prefixedBytes

    def _addPKCS1Padding(self, bytes, blockType):
        padLength = (numBytes(self.n) - (len(bytes)+3))
        if blockType == 1: #Signature padding
            pad = [0xFF] * padLength
        elif blockType == 2: #Encryption padding
            pad = bytearray(0)
            while len(pad) < padLength:
                padBytes = getRandomBytes(padLength * 2)
                pad = [b for b in padBytes if b != 0]
                pad = pad[:padLength]
        else:
            raise AssertionError()

        padding = bytearray([0,blockType] + pad + [0])
        paddedBytes = padding + bytes
        return paddedBytes




    def _rawPrivateKeyOp(self, m):
        #Create blinding values, on the first pass:
        if not self.blinder:
            self.unblinder = getRandomNumber(2, self.n)
            self.blinder = powMod(invMod(self.unblinder, self.n), self.e,
                                  self.n)

        #Blind the input
        m = (m * self.blinder) % self.n

        #Perform the RSA operation
        c = self._rawPrivateKeyOpHelper(m)

        #Unblind the output
        c = (c * self.unblinder) % self.n

        #Update blinding values
        self.blinder = (self.blinder * self.blinder) % self.n
        self.unblinder = (self.unblinder * self.unblinder) % self.n

        #Return the output
        return c


    def _rawPrivateKeyOpHelper(self, m):
        #Non-CRT version
        #c = powMod(m, self.d, self.n)

        #CRT version  (~3x faster)
        s1 = powMod(m, self.dP, self.p)
        s2 = powMod(m, self.dQ, self.q)
        h = ((s1 - s2) * self.qInv) % self.p
        c = s2 + self.q * h
        return c

    def _rawPublicKeyOp(self, c):
        m = powMod(c, self.e, self.n)
        return m

    def acceptsPassword(self):
        return False

    def generate(bits):
        key = Python_RSAKey()
        p = getRandomPrime(bits//2, False)
        q = getRandomPrime(bits//2, False)
        t = lcm(p-1, q-1)
        key.n = p * q
        key.e = 65537
        key.d = invMod(key.e, t)
        key.p = p
        key.q = q
        key.dP = key.d % (p-1)
        key.dQ = key.d % (q-1)
        key.qInv = invMod(q, p)
        return key
    generate = staticmethod(generate)

