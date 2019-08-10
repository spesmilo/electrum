#ifndef _SECP256K1_SCHNORR_
# define _SECP256K1_SCHNORR_

# include "secp256k1.h"

# ifdef __cplusplus
extern "C" {
# endif

/**
 * Verify a signature created by secp256k1_schnorr_sign.
 * Returns: 1: correct signature
 *          0: incorrect signature
 * Args:    ctx:       a secp256k1 context object, initialized for verification.
 * In:      sig64:     the 64-byte signature being verified (cannot be NULL)
 *          msg32:     the 32-byte message hash being verified (cannot be NULL)
 *          pubkey:    the public key to verify with (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorr_verify(
  const secp256k1_context* ctx,
  const unsigned char *sig64,
  const unsigned char *msg32,
  const secp256k1_pubkey *pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/**
 * Create a signature using a custom EC-Schnorr-SHA256 construction. It
 * produces non-malleable 64-byte signatures which support batch validation,
 * and multiparty signing.
 * Returns: 1: signature created
 *          0: the nonce generation function failed, or the private key was
 *             invalid.
 * Args:    ctx:    pointer to a context object, initialized for signing
 *                  (cannot be NULL)
 * Out:     sig64:  pointer to a 64-byte array where the signature will be
 *                  placed (cannot be NULL)
 * In:      msg32:  the 32-byte message hash being signed (cannot be NULL)
 *          seckey: pointer to a 32-byte secret key (cannot be NULL)
 *          noncefp:pointer to a nonce generation function. If NULL,
 *                  secp256k1_nonce_function_default is used
 *          ndata:  pointer to arbitrary data used by the nonce generation
 *                  function (can be NULL)
 */
SECP256K1_API int secp256k1_schnorr_sign(
  const secp256k1_context *ctx,
  unsigned char *sig64,
  const unsigned char *msg32,
  const unsigned char *seckey,
  secp256k1_nonce_function noncefp,
  const void *ndata
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

# ifdef __cplusplus
}
# endif

#endif
