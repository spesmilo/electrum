#!/usr/bin/env python3
#
# Electron Cash - a lightweight Bitcoin Cash client
# CashFusion - an advanced coin anonymizer
#
# Copyright (C) 2020 Mark B. Lundeberg
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
"""
Pedersen commitments on secp256k1 --

    commitment = nonce*G + amount*H

where G is the regular base point and H is a secondary base point with an
unknown discrete logarithm with respect to G. One should choose H as a
"nothing-up-my-sleeve" point with an obviously chosen x coordinate.

nonce and amount are scalars. The nonce should be randomly and uniformly
selected for each commitment, and the amount committed is a modular number.

Note that commitments to negative amounts are indistinguishable from
commitments to very large amounts. In practice, you probably need some kind
of additional mechanism (commitment reveal, range proof) to make sure the
amount is sensible.

"""

from electroncash import secp256k1
import ecdsa
from electroncash.bitcoin import ser_to_point, point_to_ser
from ctypes import create_string_buffer, c_void_p, c_char_p, c_int, c_size_t, byref, cast

order = ecdsa.SECP256k1.generator.order()
seclib = secp256k1.secp256k1

class NonceRangeError(ValueError):
    pass

class ResultAtInfinity(Exception):
    pass

class InsecureHPoint(Exception):
    # This exception gets thrown when the H point has a known discrete
    # logarithm, which means the commitment setup is broken.
    pass

class PedersenSetup:
    """
    You need to make one of these objects to set up the Pedersen scheme,
    before making any Commitment objects. One Setup object can be used for
    many Commitments.

    This stores uncompressed serializations of H and H+G as .H and .HG,
    respectively. It also stores ECC-library-specific internal representations
    of these two points.

    (Why H and H+G? To be able to blind the elliptic curve math -- see
    Commitment class comments for details)
    """
    def __init__(self, H):
        assert isinstance(H, bytes)

        if not seclib:
            try:
                Hpoint = ser_to_point(H)
            except:
                raise ValueError("H could not be parsed")
            HGpoint = Hpoint + ecdsa.SECP256k1.generator
            if HGpoint == ecdsa.ellipticcurve.INFINITY:
                # this happens if H = -G
                raise InsecureHPoint(-1)
            self._ecdsa_H = Hpoint
            self._ecdsa_HG = HGpoint

            self.H = point_to_ser(Hpoint, comp=False)
            self.HG = point_to_ser(HGpoint, comp=False)
        else:
            ctx = seclib.ctx
            H_buf = create_string_buffer(64)
            res = seclib.secp256k1_ec_pubkey_parse(ctx, H_buf, H, c_size_t(len(H)))
            if not res:
                raise ValueError('H could not be parsed by the secp256k1 library')

            self._seclib_H = H_buf.raw

            G = point_to_ser(ecdsa.SECP256k1.generator, comp=False)
            G_buf = create_string_buffer(64)
            res = seclib.secp256k1_ec_pubkey_parse(ctx, G_buf, G, c_size_t(len(G)))
            assert res, "G point should always deserialize without issue"

            HG_buf = create_string_buffer(64)
            publist = (c_void_p*2)(*(cast(x, c_void_p) for x in (H_buf, G_buf)))
            res = seclib.secp256k1_ec_pubkey_combine(ctx, HG_buf, publist, 2)
            if res != 1:
                # this happens if H = -G
                raise InsecureHPoint(-1)

            self._seclib_HG = HG_buf.raw

            # now serialize H and HG as uncompressed bytes
            serpoint = create_string_buffer(65)
            sersize = c_size_t(65)

            res = seclib.secp256k1_ec_pubkey_serialize(ctx, serpoint, byref(sersize), H_buf, secp256k1.SECP256K1_EC_UNCOMPRESSED)
            assert res == 1
            assert sersize.value == 65
            self.H = serpoint.raw

            res = seclib.secp256k1_ec_pubkey_serialize(ctx, serpoint, byref(sersize), HG_buf, secp256k1.SECP256K1_EC_UNCOMPRESSED)
            assert res == 1
            assert sersize.value == 65
            self.HG = serpoint.raw

    def commit(self, amount, nonce=None):
        return Commitment(self, amount, nonce=nonce)

class Commitment:
    """
    This represents a single commitment. Upon construction it calculates the
    commitment point, and stores the random secret nonce value.
    """
    def __init__(self, setup, amount, nonce=None, _P_uncompressed=None):
        """ setup should be a PedersenSetup object.

        amount should be an integer, may be negative or positive. The provided
        value is stored as .amount and its normal form (mod order) is stored in
        amount_mod. There is no restriction on the size nor sign of amount.

        You can also use this class to test a revealed commitment, by providing
        the nonce value. Provided nonces must be in the range 0 < nonce < order,
        or else a NonceRangeError will result.

        _P_uncompressed is an internal API variable, do not use.
        """
        assert isinstance(setup, PedersenSetup)
        self.setup = setup

        self.amount = int(amount)
        self.amount_mod = amount % order

        if nonce is None:
            self.nonce = ecdsa.util.randrange(order)
        else:
            nonce = int(nonce)
            self.nonce = nonce
        if self.nonce <= 0 or self.nonce >= order:
            raise NonceRangeError

        if _P_uncompressed:
            assert len(_P_uncompressed) == 65
            assert _P_uncompressed[0] == 4
            self.P_uncompressed = _P_uncompressed
            self.P_compressed = bytes([2 + (_P_uncompressed[-1]&1)]) + _P_uncompressed[1:33]
            return

        try:
            if seclib:
                self._calc_initial_fast()
            else:
                self._calc_initial()
        except ResultAtInfinity:
            # We have to exclude P = infinity which can't be serialized. If
            # this happens, we have discovered a serious problem.
            #
            # First, note that if it does happen, then we can trivially compute
            # the discrete logarithm of H relative to G. So we have just cracked
            # the commitment scheme.
            #
            # Most likely, this has happened intentionally:
            #
            #   - if H was chosen from the start to have a known discrete log
            #     with respect to G.
            #   - if someone has cracked the H point's discrete log
            #
            # Thus not only do we know the discrete log, but the big conclusion
            # to draw here is that someone else does, too!
            #
            # (Because 0 < nonce < order, this is basically impossible to cause
            # in a normal setup (only ~2^256 chance).)

            # As it's easy to calculate the discrete log, let's do it.
            dlog = (pow(self.amount_mod, order-2, order) * self.nonce) % order
            raise InsecureHPoint(dlog)

    def _calc_initial(self):
        Hpoint = self.setup._ecdsa_H
        HGpoint = self.setup._ecdsa_HG

        k = self.nonce
        a = self.amount_mod

        # We don't want to calculate (a * Hpoint) since the time to execute
        # would reveal information about size / bitcount of a. So, we use
        # the nonce as a blinding offset factor.
        Ppoint = ((a - k) % order) * Hpoint +  k * HGpoint

        if Ppoint == ecdsa.ellipticcurve.INFINITY:
            raise ResultAtInfinity

        self.P_uncompressed = point_to_ser(Ppoint, comp=False)
        self.P_compressed = point_to_ser(Ppoint, comp=True)

    def _calc_initial_fast(self):
        # Fast version of _calc_initial, using libsecp256k1.
        # Like in the slow version above, we need to perform a blinding of the
        # amount for timing reasons. Why?
        # - libsecp's scalar*pubkey multiplication is not constant time, though
        #   of course since it's so much faster, it's harder to attack this.
        # - amount=0 is going to be popular, and libsecp returns fail
        #   immediately if we ask it to compute 0*H.
        ctx = seclib.ctx

        k = self.nonce
        a = self.amount_mod

        # calculate k * (G + H)
        k_bytes = k.to_bytes(32,'big')
        kHG_buf = create_string_buffer(64)
        kHG_buf.raw = self.setup._seclib_HG #copy
        res = seclib.secp256k1_ec_pubkey_tweak_mul(ctx, kHG_buf, k_bytes)
        assert res == 1, "must never fail since 0 < k < order"

        a_k = (a - k) % order
        if a_k != 0:
            result_buf = create_string_buffer(64)

            # calculate (a - k) * H
            a_k_bytes = a_k.to_bytes(32,'big')
            akH_buf = create_string_buffer(64)
            akH_buf.raw = self.setup._seclib_H #copy
            res = seclib.secp256k1_ec_pubkey_tweak_mul(ctx, akH_buf, a_k_bytes)
            assert res == 1, "must never fail since a != k here"

            # add the two points together.
            publist = (c_void_p*2)(*(cast(x, c_void_p) for x in (kHG_buf, akH_buf)))
            res = seclib.secp256k1_ec_pubkey_combine(ctx, result_buf, publist, 2)
            if res != 1:
                raise ResultAtInfinity
        else:
            # a == k. this executes much faster but will almost never happen in
            # normal practice.
            result_buf = kHG_buf

        # serialize the result!
        serpoint = create_string_buffer(65)
        sersize = c_size_t(65)

        res = seclib.secp256k1_ec_pubkey_serialize(ctx, serpoint, byref(sersize), result_buf, secp256k1.SECP256K1_EC_UNCOMPRESSED)
        assert res == 1
        assert sersize.value == 65
        self.P_uncompressed = serpoint.raw

        res = seclib.secp256k1_ec_pubkey_serialize(ctx, serpoint, byref(sersize), result_buf, secp256k1.SECP256K1_EC_COMPRESSED)
        assert res == 1
        assert sersize.value == 33
        self.P_compressed = serpoint.raw[:33]

def add_points(points_iterable):
    """ Adds one or more serialized points together. This is fastest if the
    points are already uncompressed. Returns uncompressed point.

    Note: intermediate sums are allowed to be the point at infinity, but not the
    final result.
    """
    plist = []
    if seclib:
        ctx = seclib.ctx
        for pser in points_iterable:
            P_buf = create_string_buffer(64)
            _b = bytes(pser)
            res = seclib.secp256k1_ec_pubkey_parse(ctx, P_buf, _b, c_size_t(len(_b)))
            if not res:
                raise ValueError('point could not be parsed by the secp256k1 library')
            plist.append(P_buf)
        if not plist:
            raise ValueError('empty list')

        num = len(plist)
        result_buf = create_string_buffer(64)
        publist = (c_void_p*num)(*(cast(x, c_void_p) for x in plist))
        res = seclib.secp256k1_ec_pubkey_combine(ctx, result_buf, publist, num)
        if res != 1:
            raise ResultAtInfinity

        serpoint = create_string_buffer(65)
        sersize = c_size_t(65)
        res = seclib.secp256k1_ec_pubkey_serialize(ctx, serpoint, byref(sersize), result_buf, secp256k1.SECP256K1_EC_UNCOMPRESSED)
        assert res == 1
        assert sersize.value == 65
        return serpoint.raw
    else:
        for pser in points_iterable:
            plist.append(ser_to_point(pser))
        if not plist:
            raise ValueError('empty list')
        Psum = sum(plist[1:], plist[0])
        if Psum == ecdsa.ellipticcurve.INFINITY:
            raise ResultAtInfinity
        return point_to_ser(Psum, comp=False)

def add_commitments(commitment_iterable):
    """ Adds any number of Pedersen commitments together, resulting in
    another Commitment.

    commitment_list is a list of Commitment objects; they must all share
    the same PedersenSetup (else the result wouldn't make any sense)."""
    ktotal = 0
    atotal = 0
    points = []
    setups = []
    for c in commitment_iterable:
        ktotal += c.nonce
        atotal += c.amount
        points.append(c.P_uncompressed)
        setups.append(c.setup)

    if len(points) < 1:
        raise ValueError('empty list')

    setup = setups[0]
    if not all(s is setup for s in setups):
        raise ValueError('mismatched setups')

    # atotal is not computed from modulo quantities.

    ktotal = ktotal % order

    if ktotal == 0:
        # this improbable to happen by accident, but very easily occurs with
        # deliberate nonce choices.
        raise NonceRangeError

    if len(points) < 512:
        # Point addition is quite fast, when compared to doing two
        # scalar.point multiplications.
        try:
            P_uncompressed = add_points(points)
        except ResultAtInfinity:
            P_uncompressed = None # will raise exception below
    else:
        # So many points, we are better off just doing it from scalars.
        P_uncompressed = None

    return Commitment(setup, atotal, nonce=ktotal, _P_uncompressed = P_uncompressed)
