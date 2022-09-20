/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * Anatolii Kurotych <akurotych@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _DAP_ENC_KEY_H_
#define _DAP_ENC_KEY_H_

#include <stddef.h>
#include <time.h>
#include <stdint.h>
#include "dap_common.h"

typedef enum dap_enc_data_type{DAP_ENC_DATA_TYPE_RAW,

                               DAP_ENC_DATA_TYPE_B64,

                               DAP_ENC_DATA_TYPE_B64_URLSAFE,

                               } dap_enc_data_type_t;



typedef enum dap_enc_key_type{

                           DAP_ENC_KEY_TYPE_INVALID = -1,
                           DAP_ENC_KEY_TYPE_IAES, // Symmetric AES
                           DAP_ENC_KEY_TYPE_OAES,// from https://github.com/monero-project/monero/tree/master/src/crypto

                           DAP_ENC_KEY_TYPE_BF_CBC,// BlowFish CBCmode
                           DAP_ENC_KEY_TYPE_BF_OFB,//BlowFish OFBmode

                           DAP_ENC_KEY_TYPE_GOST_OFB,//GOST28147_89
                           DAP_ENC_KEY_TYPE_KUZN_OFB,//GOST28147_14

                           DAP_ENC_KEY_TYPE_SALSA2012,//SALSA2012//http://www.ecrypt.eu.org/stream/salsa20pf.html//https://ianix.com/pub/salsa20-deployment.html

                           DAP_ENC_KEY_TYPE_SEED_OFB,//SEED Cipher in OFB mode

                           DAP_ENC_KEY_TYPE_RLWE_NEWHOPE_CPA_KEM, // "NewHope": key exchange from the ring learning with errors problem
                                                //  (Alkim, Ducas, Pöppelmann, Schwabe, USENIX Security 2016 )
                                                //  Using the reference C implementation of NewHope
                                                // from https://github.com/tpoeppelmann/newhop
                                                // https://eprint.iacr.org/2015/1092

                           DAP_ENC_KEY_TYPE_SIDH_CLN16 , // Key exchange from the supersingular isogeny Diffie-Hellman problem
                                               // (Costello, Naehrig, Longa, CRYPTO 2016, https://eprint.iacr.org/2016/413)
                                               // using the implementation of Microsoft Research
                                               // https://www.microsoft.com/en-us/research/project/sidh-library/
                           DAP_ENC_KEY_TYPE_DEFEO , // Key exchange from the supersingular isogeny Diffie-Hellman problem

                           DAP_ENC_KEY_TYPE_MSRLN,

                           DAP_ENC_KEY_TYPE_RLWE_MSRLN16,
                            //DAP_ENC_KEY_TYPE_RLWE_MSRLN16, // Microsoft Research implementation of Peikert's ring-LWE key exchange
                                                // (Longa, Naehrig, CANS 2016, https://eprint.iacr.org/2016/504)
                                                // based on the implementation of Alkim, Ducas, Pöppelmann, and Schwabe,
                                                // with improvements from Longa and Naehrig,
                                                //  https://www.microsoft.com/en-us/research/project/lattice-cryptography-library/


                           DAP_ENC_KEY_TYPE_RLWE_BCNS15, // key exchange from the ring learning with errors problem
                                                     // (Bos, Costello, Naehrig, Stebila,
                                                     // IEEE Symposium on Security & Privacy 2015,
                                                     // https://eprint.iacr.org/2014/599)

                           DAP_ENC_KEY_TYPE_LWE_FRODO ,  // "Frodo": key exchange from the learning with errors problem
                                                // Bos, Costello, Ducas, Mironov, Naehrig, Nikolaenko, Raghunathan, Stebila
                                                // ACM Conference on Computer and Communications Security 2016
                                                // https://eprint.iacr.org/2016/659

                           DAP_ENC_KEY_TYPE_SIDH_IQC_REF, // key exchange from the supersingular isogeny Diffie-Hellman problem
                                                 // (De Feo, Jao, Plût, J. Math. Cryptol. 8(3):209, 2014
                                                 // https://eprint.iacr.org/2011/506
                                                 //
                           DAP_ENC_KEY_TYPE_CODE_MCBITS, // "McBits": key exchange from the error correcting codes,
                                                // specifically Niederreiter's form of McEliece public key encryption
                                                //  using hidden Goppa codes (Bernstein, Chou, Schwabe, CHES 2013, https://eprint.iacr.org/2015/610)
                                                // using the implementation of McBits from https://www.win.tue.nl/~tchou/mcbits/

                           DAP_ENC_KEY_TYPE_NTRU,   // NTRU: key transport using NTRU public key encryption
                                               // (Hoffstein, Pipher, Silverman, ANTS 1998) with the EES743EP1 parameter set
                                               //  wrapper around the implementation from the NTRU Open Source project
                                               // https://github.com/NTRUOpenSourceProject/NTRUEncrypt)

                           DAP_ENC_KEY_TYPE_MLWE_KYBER, // Kyber: a CCA-secure module-lattice-based key exchange mechanism
                                               // (Bos, Ducas, Kiltz, Lepoint, Lyubashevsky, Schwabe, Shanck, Stehlé)
                                               // Real World Crypto 2017, https://eprint.iacr.org/2017/634)
                                               // using the reference C implementation of Kyber from pq-crystals/kyber
                           DAP_ENC_KEY_TYPE_SIG_PICNIC,  // signature based on zero-knowledge proof as specified in
                                               // Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives
                                               // (Melissa Chase and David Derler and Steven Goldfeder and Claudio Orlandi
                                               // and Sebastian Ramacher and Christian Rechberger and Daniel Slamanig and Greg Zaverucha
                                               // https://eprint.iacr.org/2017/279.pdf), using the optimized implemenation
                                               //  from https://github.com/IAIK/Picnic
                           DAP_ENC_KEY_TYPE_SIG_BLISS,  // signature based on zero-knowledge proof as specified in
                                               // Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives

                           DAP_ENC_KEY_TYPE_SIG_TESLA,  // signature based on Ring_LWE problem with zero-knowledge proof as specified in
                                               // Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives

                           DAP_ENC_KEY_TYPE_SIG_DILITHIUM,

                           DAP_ENC_KEY_TYPE_SIG_RINGCT20,//ring signature for confidentional transaction

                           DAP_ENC_KEY_TYPE_KEM_KYBER512, // NIST Kyber KEM implementation
                           DAP_ENC_KEY_TYPE_LAST = DAP_ENC_KEY_TYPE_KEM_KYBER512,
                           DAP_ENC_KEY_TYPE_NULL = 0 // avoid using it: 0 is a DAP_ENC_KEY_TYPE_NULL and DAP_ENC_KEY_TYPE_IAES at the same time

                         }  dap_enc_key_type_t;

struct dap_enc_key;

// allocates memory and sets callbacks
typedef void (*dap_enc_callback_new)(struct dap_enc_key*);

// generates key data from seed
typedef void (*dap_enc_callback_new_generate)(struct dap_enc_key* key, const void *kex_buf,
                                              size_t kex_size, const void* seed, size_t seed_size,
                                              size_t key_size);
// free memory
typedef void (*dap_enc_callback_delete)(struct dap_enc_key*);

typedef size_t (*dap_enc_callback_key_size_t)(struct dap_enc_key*);

// encrypt and decrypt functions. Allocates Memory for out
typedef size_t (*dap_enc_callback_dataop_t)(struct dap_enc_key *key, const void *in,
                                            const size_t in_size,void ** out);

typedef size_t (*dap_enc_callback_dataop_na_t)(struct dap_enc_key *key, const void *in,
                                            const size_t in_size,void * out, const size_t out_size_max);
typedef size_t (*dap_enc_callback_dataop_na_ext_t)(struct dap_enc_key *key, const void *in,
                                            const size_t in_size,void * out, const size_t out_size_max, const void *extra_param, const int extra_param_len);

typedef int (*dap_enc_callback_sign_op_t)(struct dap_enc_key *key, const void *in,
                                            const size_t in_size,void * out, const size_t out_size_max);

// key pair generation and generation of shared key at Bob's side
// INPUT:
// dap_enc_key *b_key
// a_pub  ---  Alice's public key
// a_pub_size --- Alice's public key length
// OUTPUT:
// b_pub  --- Bob's public key
// b_key->priv_key_data --- shared key
// b_key->priv_key_data_size --- shared key length
typedef size_t (*dap_enc_gen_bob_shared_key) (struct dap_enc_key *b_key, const void *a_pub,
                                           size_t a_pub_size, void ** b_pub);

// generation of shared key at Alice's side
// INPUT:
// dap_enc_key *a_key
// a_priv  --- Alice's private key
// b_pub  ---  Bob's public key
// b_pub_size --- Bob public key size
// OUTPUT:
// a_key->priv_key_data  --- shared key
// a_key->priv_key_data_size --- shared key length
typedef size_t (*dap_enc_gen_alice_shared_key) (struct dap_enc_key *a_key, const void *a_priv,
                                             size_t b_pub_size, unsigned char *b_pub);

typedef int (*dap_enc_callback_gen_key_public_t ) (struct dap_enc_key *a_key, void * a_output);

typedef void (*dap_enc_callback_ptr_t)(struct dap_enc_key *, void *);
typedef size_t (*dap_enc_callback_pptr_r_size_t)(struct dap_enc_key *, void **);
typedef void (*dap_enc_callback_data_t)(struct dap_enc_key *, const void * , size_t);
typedef void (*dap_enc_callback_size_t)(struct dap_enc_key *, size_t);
typedef void (*dap_enc_callback_str_t)(struct dap_enc_key *, const char*);
typedef char* (*dap_enc_callback_r_str_t)(struct dap_enc_key *);
typedef size_t (*dap_enc_callback_calc_out_size)(const size_t);
typedef size_t (*dap_enc_get_allpbk_list) (struct dap_enc_key *a_key, const void *allpbk_list, const int allpbk_num);

typedef struct dap_enc_key {
    union{
        size_t priv_key_data_size;
        size_t shared_key_size;
    };
    //unsigned char * priv_key_data; // can be shared key in assymetric alghoritms
    union{
        void * priv_key_data; // can be shared key in assymetric alghoritms or secret key in signature alghoritms
        byte_t * shared_key;
    };

    size_t pub_key_data_size;
    //unsigned char * pub_key_data; // can be null if enc symmetric
    void * pub_key_data; // can be null if enc symmetric

    time_t last_used_timestamp;
    dap_enc_key_type_t type;
    dap_enc_callback_dataop_t enc;
    dap_enc_callback_dataop_t dec;
    dap_enc_callback_dataop_na_t enc_na;
    dap_enc_callback_dataop_na_t dec_na;
    dap_enc_callback_dataop_na_ext_t dec_na_ext;

    dap_enc_callback_sign_op_t sign_get;
    dap_enc_callback_sign_op_t sign_verify;

    dap_enc_gen_alice_shared_key gen_alice_shared_key;
    dap_enc_gen_bob_shared_key gen_bob_shared_key;

    void *pbkListdata;
    size_t pbkListsize;
    dap_enc_get_allpbk_list getallpbkList;


    void * _inheritor; // WARNING! Inheritor must have only serealizeble/deserializeble data (copy)
    size_t _inheritor_size;
} dap_enc_key_t;

#define MAX_ENC_KEY_SIZE 16384
#define MAX_INHERITOR_SIZE 2048

// struct for serelization/deseralization keys in binary storage
typedef struct dap_enc_key_serealize {
    size_t priv_key_data_size;
    size_t pub_key_data_size;
    size_t inheritor_size;
    time_t last_used_timestamp;
    dap_enc_key_type_t type;

    unsigned char priv_key_data[MAX_ENC_KEY_SIZE];
    unsigned char pub_key_data[MAX_ENC_KEY_SIZE];
    unsigned char inheritor[MAX_INHERITOR_SIZE];
} dap_enc_key_serealize_t;

#ifdef __cplusplus
extern "C" {
#endif

int dap_enc_key_init(void);
void dap_enc_key_deinit(void);

const char *dap_enc_get_type_name(dap_enc_key_type_t a_key_type);
dap_enc_key_type_t dap_enc_key_type_find_by_name(const char * a_name);
size_t dap_enc_key_get_enc_size(dap_enc_key_t * a_key, const size_t buf_in_size);
size_t dap_enc_key_get_dec_size(dap_enc_key_t * a_key, const size_t buf_in_size);

uint8_t* dap_enc_key_serealize_sign(dap_enc_key_type_t a_key_type, uint8_t *a_sign, size_t *a_sign_len);
uint8_t* dap_enc_key_deserealize_sign(dap_enc_key_type_t a_key_type, uint8_t *a_sign, size_t *a_sign_len);
uint8_t* dap_enc_key_serealize_priv_key(dap_enc_key_t *a_key, size_t *a_buflen_out);
uint8_t* dap_enc_key_serealize_pub_key(dap_enc_key_t *a_key, size_t *a_buflen_out);
int dap_enc_key_deserealize_priv_key(dap_enc_key_t *a_key, const uint8_t *a_buf, size_t a_buflen);
int dap_enc_key_deserealize_pub_key(dap_enc_key_t *a_key, const uint8_t *a_buf, size_t a_buflen);
int dap_enc_key_deserealize_pub_key_old(dap_enc_key_t *a_key, const uint8_t *a_buf, size_t a_buflen);

dap_enc_key_serealize_t* dap_enc_key_serealize(dap_enc_key_t * key);
dap_enc_key_t* dap_enc_key_deserealize(const void *buf, size_t buf_size);
dap_enc_key_t* dap_enc_key_dup(dap_enc_key_t * a_key);

// allocate memory for key struct
dap_enc_key_t *dap_enc_key_new(dap_enc_key_type_t a_key_type);


// default gen key
dap_enc_key_t *dap_enc_key_new_generate(dap_enc_key_type_t key_type, const void *kex_buf,
                                                      size_t kex_size, const void* seed,
                                                      size_t seed_size, size_t key_size);

// update struct dap_enc_key_t after insert foreign keys
void dap_enc_key_update(dap_enc_key_t *a_key);

// for asymmetric gen public key
dap_enc_key_t *dap_enc_gen_pub_key_from_priv(struct dap_enc_key *a_key, void **priv_key, size_t *alice_msg_len);


size_t dap_enc_gen_key_public_size (dap_enc_key_t *a_key);
int dap_enc_gen_key_public (dap_enc_key_t *a_key, void * a_output);

void dap_enc_key_signature_delete(dap_enc_key_type_t a_key_type, uint8_t *a_sig_buf);
void dap_enc_key_delete(dap_enc_key_t * a_key);

#ifdef __cplusplus
}
#endif

#endif
