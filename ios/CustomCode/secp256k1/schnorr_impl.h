/***********************************************************************
 * Copyright (c) 2017 Amaury SÉCHET                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. *
 ***********************************************************************/

#ifndef _SECP256K1_SCHNORR_IMPL_H_
#define _SECP256K1_SCHNORR_IMPL_H_

#include <string.h>

#include "schnorr.h"
#include "field.h"
#include "group.h"
#include "hash.h"
#include "ecmult.h"
#include "ecmult_gen.h"

/**
 * Custom Schnorr-based signature scheme.
 *
 * Signing:
 *   Inputs:
 *     32-byte message m,
 *     32-byte scalar key x (!=0)
 *     public key point P,
 *     32-byte scalar nonce k (!=0)
 *
 *   Compute point R = k * G. Negate nonce if R.y is not a quadratic residue.
 *   Compute scalar e = Hash(R.x || compressed(P) || m) mod n.
 *   Compute scalar s = k + e * x.
 *   The signature is (R.x, s).
 *
 * Verification:
 *   Inputs:
 *     32-byte message m,
 *     public key point P,
 *     signature: (32-byte r, scalar s)
 *
 *   Signature is invalid if s >= n or r >= p.
 *   Compute scalar e = Hash(r || compressed(P) || m) mod n.
 *   Option 1 (faster for single verification):
 *     Compute point R = s * G - e * P.
 *       Reject if R is infinity or R.y is not a quadratic residue.
 *       Signature is valid if the serialization of R.x equals r.
 *   Option 2 (allows batch validation):
 *     Decompress x coordinate r into point R, with R.y a quadratic residue.
 *       Reject if R is not on the curve.
 *       Signature is valid if R + e * P - s * G == 0.
 */
static int secp256k1_schnorr_sig_verify(
    const secp256k1_ecmult_context* ctx,
    const unsigned char *sig64,
    secp256k1_ge *pubkey,
    const unsigned char *msg32
) {
    secp256k1_gej Pj, Rj;
    secp256k1_fe Rx;
    secp256k1_scalar e, s;
    int overflow;

    if (secp256k1_ge_is_infinity(pubkey)) {
        return 0;
    }

    /* Extract s */
    overflow = 0;
    secp256k1_scalar_set_b32(&s, sig64 + 32, &overflow);
    if (overflow) {
        return 0;
    }

    /* Extract R.x */
    if (!secp256k1_fe_set_b32(&Rx, sig64)) {
        return 0;
    }

    /* Compute e */
    secp256k1_schnorr_compute_e(&e, sig64, pubkey, msg32);

    /* Verify the signature */
    secp256k1_scalar_negate(&e, &e);
    secp256k1_gej_set_ge(&Pj, pubkey);
    secp256k1_ecmult(ctx, &Rj, &Pj, &e, &s);
    if (secp256k1_gej_is_infinity(&Rj)) {
        return 0;
    }

    /* Check that R.x is what we expect */
    if (!secp256k1_gej_eq_x_var(&Rx, &Rj)) {
        return 0;
    }

    /* Check that jacobi(R.y) is 1 */
    if (!secp256k1_gej_has_quad_y_var(&Rj)) {
        return 0;
    }

    /* All good, we have a valid signature. */
    return 1;
}

static int secp256k1_schnorr_compute_e(
    secp256k1_scalar* e,
    const unsigned char *r,
    secp256k1_ge *p,
    const unsigned char *msg32
) {
    int overflow = 0;
    size_t size;
    secp256k1_sha256 sha;
    unsigned char buf[33];
    secp256k1_sha256_initialize(&sha);

    /* R.x */
    secp256k1_sha256_write(&sha, r, 32);

    /* compressed P */
    secp256k1_eckey_pubkey_serialize(p, buf, &size, 1);
    VERIFY_CHECK(size == 33);
    secp256k1_sha256_write(&sha, buf, 33);

    /* msg */
    secp256k1_sha256_write(&sha, msg32, 32);

    /* compute e */
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(e, buf, &overflow);
    return !overflow & !secp256k1_scalar_is_zero(e);
}

static int secp256k1_schnorr_sig_sign(
    const secp256k1_ecmult_gen_context* ctx,
    unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_scalar *privkey,
    secp256k1_ge *pubkey,
    secp256k1_nonce_function noncefp,
    const void *ndata
) {
    secp256k1_ge R;
    secp256k1_scalar k;
    int ret;

    if (secp256k1_scalar_is_zero(privkey)) {
        return 0;
    }

    if (!secp256k1_schnorr_compute_k_R(ctx, &k, &R, msg32, privkey, noncefp, ndata)) {
        return 0;
    }

    ret = secp256k1_schnorr_compute_sig(sig64, msg32, &k, &R, privkey, pubkey);
    secp256k1_scalar_clear(&k);
    return ret;
}

static int secp256k1_schnorr_compute_k_R(
    const secp256k1_ecmult_gen_context* ctx,
    secp256k1_scalar *k,
    secp256k1_ge *R,
    const unsigned char *msg32,
    const secp256k1_scalar *privkey,
    secp256k1_nonce_function noncefp,
    const void *ndata
) {
    secp256k1_gej Rj;

    if (!secp256k1_schnorr_sig_generate_k(k, msg32, privkey, noncefp, ndata)) {
        return 0;
    }

    secp256k1_ecmult_gen(ctx, &Rj, k);
    secp256k1_ge_set_gej(R, &Rj);
    return 1;
}

static int secp256k1_schnorr_compute_sig(
    unsigned char *sig64,
    const unsigned char *msg32,
    secp256k1_scalar *k,
    secp256k1_ge *R,
    const secp256k1_scalar *privkey,
    secp256k1_ge *pubkey
) {
    secp256k1_scalar e, s;

    if (secp256k1_scalar_is_zero(privkey) || secp256k1_scalar_is_zero(k)) {
        return 0;
    }

    if (secp256k1_ge_is_infinity(pubkey)) {
        return 0;
    }

    if (!secp256k1_fe_is_quad_var(&R->y)) {
        /**
         * R's y coordinate is not a quadratic residue, which is not allowed.
         * Negate the nonce to ensure it is.
         */
        secp256k1_scalar_negate(k, k);
    }

    secp256k1_fe_normalize(&R->x);
    secp256k1_fe_get_b32(sig64, &R->x);
    secp256k1_schnorr_compute_e(&e, sig64, pubkey, msg32);
    secp256k1_scalar_mul(&s, &e, privkey);
    secp256k1_scalar_add(&s, &s, k);
    secp256k1_scalar_get_b32(sig64 + 32, &s);
    return 1;
}

static int secp256k1_schnorr_sig_generate_k(
    secp256k1_scalar *k,
    const unsigned char *msg32,
    const secp256k1_scalar *privkey,
    secp256k1_nonce_function noncefp,
    const void *ndata
) {
    int overflow = 0;
    int ret = 0;
    unsigned int count = 0;
    unsigned char nonce32[32], seckey[32];

    /* Seed used to make sure we generate different values of k for schnorr */
    const unsigned char secp256k1_schnorr_algo16[17] = "Schnorr+SHA256  ";

    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_default;
    }

    secp256k1_scalar_get_b32(seckey, privkey);
    while (1) {
        ret = noncefp(nonce32, msg32, seckey, secp256k1_schnorr_algo16, (void*)ndata, count++);
        if (!ret) {
            break;
        }

        secp256k1_scalar_set_b32(k, nonce32, &overflow);
        if (!overflow && !secp256k1_scalar_is_zero(k)) {
            break;
        }

        secp256k1_scalar_clear(k);
    }

    memset(seckey, 0, 32);
    memset(nonce32, 0, 32);
    return ret;
}

#endif
