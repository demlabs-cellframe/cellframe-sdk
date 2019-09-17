/*
 * Authors:
 * Dmitriy Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Anatoly Kurotych <anatoly.kurotych@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2019
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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

//#include "../sig_picnic/picnic.h"
#include "dap_enc_key.h"


#define DAP_PICNIC_SIGN_PARAMETR 1//determination of the scheme and level of resistance {1-6}

void dap_enc_sig_picnic_key_new(struct dap_enc_key *key);

void dap_enc_sig_picnic_key_delete(struct dap_enc_key *key);

void dap_enc_sig_picnic_update(struct dap_enc_key * key);

void dap_enc_sig_picnic_key_new_generate(struct dap_enc_key * key, const void *kex_buf, size_t kex_size,
        const void * seed, size_t seed_size,
        size_t key_size);

size_t dap_enc_sig_picnic_get_sign(struct dap_enc_key * key, const void* message, size_t message_len,
        void* signature, size_t signature_len);

size_t dap_enc_sig_picnic_verify_sign(struct dap_enc_key * key, const void* message, size_t message_len,
        void* signature, size_t signature_len);

size_t dap_enc_picnic_calc_signature_size(struct dap_enc_key *key);

#ifdef __cplusplus
}
#endif

