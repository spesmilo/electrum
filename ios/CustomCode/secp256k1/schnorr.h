/***********************************************************************
 * Copyright (c) 2017 Amaury SÉCHET                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. *
 ***********************************************************************/

#ifndef _SECP256K1_MODULE_SCHNORR_H_
#define _SECP256K1_MODULE_SCHNORR_H_

#include "scalar.h"
#include "group.h"

static int secp256k1_schnorr_sig_verify(
    const secp256k1_ecmult_context* ctx,
    const unsigned char *sig64,
    secp256k1_ge *pubkey,
    const unsigned char *msg32
);

static int secp256k1_schnorr_compute_e(
    secp256k1_scalar* res,
    const unsigned char *r,
    secp256k1_ge *pubkey,
    const unsigned char *msg32
);

static int secp256k1_schnorr_sig_sign(
    const secp256k1_ecmult_gen_context* ctx,
    unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_scalar *privkey,
    secp256k1_ge *pubkey,
    secp256k1_nonce_function noncefp,
    const void *ndata
);

static int secp256k1_schnorr_compute_k_R(
    const secp256k1_ecmult_gen_context* ctx,
    secp256k1_scalar *k,
    secp256k1_ge *R,
    const unsigned char *msg32,
    const secp256k1_scalar *privkey,
    secp256k1_nonce_function noncefp,
    const void *ndata
);

static int secp256k1_schnorr_compute_sig(
    unsigned char *sig64,
    const unsigned char *msg32,
    secp256k1_scalar *k,
    secp256k1_ge *R,
    const secp256k1_scalar *privkey,
    secp256k1_ge *pubkey
);

static int secp256k1_schnorr_sig_generate_k(
    secp256k1_scalar *k,
    const unsigned char *msg32,
    const secp256k1_scalar *privkey,
    secp256k1_nonce_function noncefp,
    const void *ndata
);

#endif
