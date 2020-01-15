/*! @file picnic.h
 *  @brief Public API for the Picnic signature scheme.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */


#ifndef PICNIC_H
#define PICNIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>
#include "picnic_impl.h"
#include "../rand/dap_rand.h"


/* Maximum lengths in bytes */
#define PICNIC_MAX_LOWMC_BLOCK_SIZE 32
#define PICNIC_MAX_PUBLICKEY_SIZE  (2*PICNIC_MAX_LOWMC_BLOCK_SIZE + 1)     /**< Largest serialized public key size, in bytes */
#define PICNIC_MAX_PRIVATEKEY_SIZE (3*PICNIC_MAX_LOWMC_BLOCK_SIZE + 2)     /**< Largest serialized private key size, in bytes */
#define PICNIC_MAX_SIGNATURE_SIZE  209474                                  /**< Largest signature size, in bytes */

/** Parameter set names */
typedef enum picnic_params_t {
    PARAMETER_SET_INVALID = 0,
    Picnic_L1_FS = 1,
    Picnic_L1_UR = 2,
    Picnic_L3_FS = 3,
    Picnic_L3_UR = 4,
    Picnic_L5_FS = 5,
    Picnic_L5_UR = 6,
    PARAMETER_SET_MAX_INDEX = 7
} picnic_params_t;

/** Public key */
typedef struct {
    picnic_params_t params;                                     /**< The parameter set used with this public key. */
    uint8_t plaintext[PICNIC_MAX_LOWMC_BLOCK_SIZE];           /**< The input plaintext block to LowMC. */
    uint8_t ciphertext[PICNIC_MAX_LOWMC_BLOCK_SIZE];          /**< The encryption of plaintext under the private key. */
} picnic_publickey_t;

/** Private key */
typedef struct {
    picnic_params_t params;                             /**< The parameter set used with this private key. */
    uint8_t data[PICNIC_MAX_LOWMC_BLOCK_SIZE];           /**< The private key data. */
    picnic_publickey_t pk;                              /**< The corresponding public key.  */
} picnic_privatekey_t;


/* Signature API */

size_t picnic_signature_size(picnic_params_t parameters);
size_t picnic_get_public_key_size(const picnic_publickey_t* key);/* Get public key size for serialize */
int picnic_write_public_key(const picnic_publickey_t* key, uint8_t* buf, size_t buflen);
int picnic_read_public_key(picnic_publickey_t* key, const uint8_t* buf, size_t buflen);
int picnic_write_private_key(const picnic_privatekey_t* key, uint8_t* buf, size_t buflen);
int picnic_read_private_key(picnic_privatekey_t* key, const uint8_t* buf, size_t buflen);
int picnic_validate_keypair(const picnic_privatekey_t* privatekey, const picnic_publickey_t* publickey);

void picnic_keypair_delete(picnic_privatekey_t* sk, picnic_publickey_t *pk);

int picnic_keys_gen(picnic_privatekey_t *sk, picnic_publickey_t *pk, picnic_params_t param, const void * seed, size_t seed_size);

int get_param_set(picnic_params_t picnicParams, paramset_t* paramset);

#ifdef __cplusplus
}
#endif

#endif /*PICNIC_H*/
