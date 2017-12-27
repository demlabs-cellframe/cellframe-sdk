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

typedef enum dap_enc_data_type{DAP_ENC_DATA_TYPE_RAW,
                               DAP_ENC_DATA_TYPE_B64,
                               } dap_enc_data_type_t;

typedef enum dap_enc_key_type{ DAP_ENC_KEY_TYPE_AES, // Symmetric AES

                           DAP_ENC_KEY_rlwe_bcns15, // key exchange from the ring learning with errors problem
                                                // (Bos, Costello, Naehrig, Stebila,
                                                // IEEE Symposium on Security & Privacy 2015,
                                                // https://eprint.iacr.org/2014/599)

                           DAP_ENC_KEY_rlwe_newhope, // "NewHope": key exchange from the ring learning with errors problem
                                                //  (Alkim, Ducas, Pöppelmann, Schwabe, USENIX Security 2016 )
                                                //  Using the reference C implementation of NewHope
                                                // from https://github.com/tpoeppelmann/newhop
                                                // https://eprint.iacr.org/2015/1092

                           DAP_ENC_KEY_rlwe_msrln16, // Microsoft Research implementation of Peikert's ring-LWE key exchange
                                               // (Longa, Naehrig, CANS 2016, https://eprint.iacr.org/2016/504)
                                               // based on the implementation of Alkim, Ducas, Pöppelmann, and Schwabe,
                                               // with improvements from Longa and Naehrig,
                                               //  https://www.microsoft.com/en-us/research/project/lattice-cryptography-library/

                           DAP_ENC_KEY_lwe_frodo,  // "Frodo": key exchange from the learning with errors problem
                                               // Bos, Costello, Ducas, Mironov, Naehrig, Nikolaenko, Raghunathan, Stebila
                                               // ACM Conference on Computer and Communications Security 2016
                                               // https://eprint.iacr.org/2016/659

                           DAP_ENC_KEY_sidh_cln16, // Key exchange from the supersingular isogeny Diffie-Hellman problem
                                               // (Costello, Naehrig, Longa, CRYPTO 2016, https://eprint.iacr.org/2016/413)
                                               // using the implementation of Microsoft Research
                                               // https://www.microsoft.com/en-us/research/project/sidh-library/

                           DAP_ENC_KEY_sidh_iqc_ref, // key exchange from the supersingular isogeny Diffie-Hellman problem
                                                 // (De Feo, Jao, Plût, J. Math. Cryptol. 8(3):209, 2014
                                                 // https://eprint.iacr.org/2011/506
                                                 //
                           DAP_ENC_KEY_code_mcbits, // "McBits": key exchange from the error correcting codes,
                                                // specifically Niederreiter's form of McEliece public key encryption
                                                //  using hidden Goppa codes (Bernstein, Chou, Schwabe, CHES 2013, https://eprint.iacr.org/2015/610)
                                                // using the implementation of McBits from https://www.win.tue.nl/~tchou/mcbits/

                           DAP_ENC_KEY_ntru,       // NTRU: key transport using NTRU public key encryption
                                               // (Hoffstein, Pipher, Silverman, ANTS 1998) with the EES743EP1 parameter set
                                               //  wrapper around the implementation from the NTRU Open Source project
                                               // https://github.com/NTRUOpenSourceProject/NTRUEncrypt)

                           DAP_ENC_KEY_mlwe_kyber, // Kyber: a CCA-secure module-lattice-based key exchange mechanism
                                               // (Bos, Ducas, Kiltz, Lepoint, Lyubashevsky, Schwabe, Shanck, Stehlé)
                                               // Real World Crypto 2017, https://eprint.iacr.org/2017/634)
                                               // using the reference C implementation of Kyber from pq-crystals/kyber
                           DAP_ENC_KEY_sig_picnic, // signature based on zero-knowledge proof as specified in
                                               // Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives
                                               // (Melissa Chase and David Derler and Steven Goldfeder and Claudio Orlandi
                                               // and Sebastian Ramacher and Christian Rechberger and Daniel Slamanig and Greg Zaverucha
                                               // https://eprint.iacr.org/2017/279.pdf), using the optimized implemenation
                                               //  from https://github.com/IAIK/Picnic
                         } enc_key_type_t;

struct enc_key;
typedef size_t (*enc_callback_t)(struct enc_key *, const void * , const size_t ,void *);

typedef struct enc_key{
    unsigned char * data;
    size_t data_size;
    enc_key_type_t type;

    enc_callback_t enc;
    enc_callback_t dec;

    void * internal;
} enc_key_t;

extern enc_key_t *enc_key_new(size_t key_size,enc_key_type_t key_type);
extern enc_key_t *enc_key_generate(enc_data_type_t v_type, rsa_key_t* key_session_pair);
extern enc_key_t *enc_key_create(const char * key_input,enc_key_type_t v_type);
extern void enc_key_delete(enc_key_t * key);
extern rsa_key_t* enc_key_session_pair_create(const char* client_pub_key, u_int16_t key_len);

#endif
