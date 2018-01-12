/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _DAP_ENC_KEY_H_
#define _DAP_ENC_KEY_H_

#include <stddef.h>
#include <time.h>
typedef enum dap_enc_data_type{DAP_ENC_DATA_TYPE_RAW,
                               DAP_ENC_DATA_TYPE_B64,
                               } dap_enc_data_type_t;

typedef enum dap_enc_key_type{ DAP_ENC_KEY_TYPE_AES, // Symmetric AES

                           DAP_ENC_KEY_TYPE_RLWE_BCNS15, // key exchange from the ring learning with errors problem
                                                // (Bos, Costello, Naehrig, Stebila,
                                                // IEEE Symposium on Security & Privacy 2015,
                                                // https://eprint.iacr.org/2014/599)

                           DAP_ENC_KEY_TYPE_RLWE_NEWHOPE, // "NewHope": key exchange from the ring learning with errors problem
                                                //  (Alkim, Ducas, Pöppelmann, Schwabe, USENIX Security 2016 )
                                                //  Using the reference C implementation of NewHope
                                                // from https://github.com/tpoeppelmann/newhop
                                                // https://eprint.iacr.org/2015/1092

                           DAP_ENC_KEY_TYPE_RLWE_MSRLN16, // Microsoft Research implementation of Peikert's ring-LWE key exchange
                                               // (Longa, Naehrig, CANS 2016, https://eprint.iacr.org/2016/504)
                                               // based on the implementation of Alkim, Ducas, Pöppelmann, and Schwabe,
                                               // with improvements from Longa and Naehrig,
                                               //  https://www.microsoft.com/en-us/research/project/lattice-cryptography-library/

                           DAP_ENC_KEY_TYPE_LWE_FRODO ,  // "Frodo": key exchange from the learning with errors problem
                                               // Bos, Costello, Ducas, Mironov, Naehrig, Nikolaenko, Raghunathan, Stebila
                                               // ACM Conference on Computer and Communications Security 2016
                                               // https://eprint.iacr.org/2016/659

                           DAP_ENC_KEY_TYPE_SIDH_CLN16 , // Key exchange from the supersingular isogeny Diffie-Hellman problem
                                               // (Costello, Naehrig, Longa, CRYPTO 2016, https://eprint.iacr.org/2016/413)
                                               // using the implementation of Microsoft Research
                                               // https://www.microsoft.com/en-us/research/project/sidh-library/

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
                           DAP_ENC_KEY_TYPE_SIG_PICNIC  // signature based on zero-knowledge proof as specified in
                                               // Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives
                                               // (Melissa Chase and David Derler and Steven Goldfeder and Claudio Orlandi
                                               // and Sebastian Ramacher and Christian Rechberger and Daniel Slamanig and Greg Zaverucha
                                               // https://eprint.iacr.org/2017/279.pdf), using the optimized implemenation
                                               //  from https://github.com/IAIK/Picnic
                         } dap_enc_key_type_t;

struct dap_enc_key;

typedef void (*dap_enc_callback_t)(struct dap_enc_key *);
typedef void (*dap_enc_callback_ptr_t)(struct dap_enc_key *, void *);
typedef size_t (*dap_enc_callback_pptr_r_size_t)(struct dap_enc_key *, void **);
typedef void (*dap_enc_callback_data_t)(struct dap_enc_key *, const void * , size_t);
typedef void (*dap_enc_callback_size_t)(struct dap_enc_key *, size_t);

typedef void (*dap_enc_callback_str_t)(struct dap_enc_key *, const char*);
typedef char* (*dap_enc_callback_r_str_t)(struct dap_enc_key *);


typedef size_t (*dap_enc_callback_dataop_t)(struct dap_enc_key *, const void * , const size_t ,void *);

typedef struct dap_enc_key{
    size_t data_size;
    time_t last_used_timestamp;
    unsigned char * data;
    dap_enc_key_type_t type;

    dap_enc_callback_dataop_t enc;
    dap_enc_callback_dataop_t dec;
    dap_enc_callback_t delete_callback;

    void * _inheritor;
} dap_enc_key_t;

int dap_enc_key_init();
void dap_enc_key_deinit();

dap_enc_key_t *dap_enc_key_new(dap_enc_key_type_t a_key_type);

dap_enc_key_t *dap_enc_key_new_generate(dap_enc_key_type_t a_key_type, size_t a_key_size);
dap_enc_key_t *dap_enc_key_new_from_data(dap_enc_key_type_t a_key_type, void * a_key_input, size_t a_key_input_size);
dap_enc_key_t *dap_enc_key_new_from_str(dap_enc_key_type_t a_key_type, const char *a_key_str);
void dap_enc_key_delete(dap_enc_key_t * a_key);

#endif
