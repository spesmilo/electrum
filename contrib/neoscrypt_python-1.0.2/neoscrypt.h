// Copyright (C) 2019 The Xaya developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

void neoscrypt(const unsigned char *input, unsigned char *output);

#define SCRYPT_BLOCK_SIZE 64
#define SCRYPT_HASH_BLOCK_SIZE 64
#define SCRYPT_HASH_DIGEST_SIZE 32

typedef uint8_t hash_digest[SCRYPT_HASH_DIGEST_SIZE];

#define ROTL32(a,b) (((a) << (b)) | ((a) >> (32 - b)))
#define ROTR32(a,b) (((a) >> (b)) | ((a) << (32 - b)))

#define U8TO32_BE(p) \
    (((uint32_t)((p)[0]) << 24) | ((uint32_t)((p)[1]) << 16) | \
    ((uint32_t)((p)[2]) <<  8) | ((uint32_t)((p)[3])))

#define U32TO8_BE(p, v) \
    (p)[0] = (uint8_t)((v) >> 24); (p)[1] = (uint8_t)((v) >> 16); \
    (p)[2] = (uint8_t)((v) >>  8); (p)[3] = (uint8_t)((v)      );

#define U64TO8_BE(p, v) \
    U32TO8_BE((p),     (uint32_t)((v) >> 32)); \
    U32TO8_BE((p) + 4, (uint32_t)((v)      ));
