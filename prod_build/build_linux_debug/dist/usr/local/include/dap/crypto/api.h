#ifndef SPX_API_H
#define SPX_API_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

#define SPX_CRYPTO_ALGNAME "SPHINCS+"

#define SPX_CRYPTO_SECRETKEYBYTES SPX_SK_BYTES
#define SPX_CRYPTO_PUBLICKEYBYTES SPX_PK_BYTES
#define SPX_CRYPTO_BYTES SPX_BYTES
#define SPX_CRYPTO_SEEDBYTES 3*SPX_N

/*
 * Returns the length of a secret key, in bytes
 */
uint64_t sphincsplus_crypto_sign_secretkeybytes(void);

/*
 * Returns the length of a public key, in bytes
 */
uint64_t sphincsplus_crypto_sign_publickeybytes(void);

/*
 * Returns the length of a signature, in bytes
 */
uint64_t sphincsplus_crypto_sign_bytes(void);

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
uint64_t sphincsplus_crypto_sign_seedbytes(void);

/*
 * Generates a SPHINCS+ key pair given a seed.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int sphincsplus_crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed);

/*
 * Generates a SPHINCS+ key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int sphincsplus_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

/**
 * Returns an array containing a detached signature.
 */
int sphincsplus_crypto_sign_signature(uint8_t *sig, uint64_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk);

/**
 * Verifies a detached signature and message under a given public key.
 */
int sphincsplus_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk);

/**
 * Returns an array containing the signature followed by the message.
 */
int sphincsplus_crypto_sign(unsigned char *sm, uint64_t *smlen,
                const unsigned char *m, uint64_t mlen,
                const unsigned char *sk);

/**
 * Verifies a given signature-message pair under a given public key.
 */
int sphincsplus_crypto_sign_open(unsigned char *m, uint64_t *mlen,
                     const unsigned char *sm, uint64_t smlen,
                     const unsigned char *pk);

#endif
