/*
 * Authors:
 * Dmitriy Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Anatoly Kurotych <anatoly.kurotych@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2019
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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

void dap_enc_sig_picnic_key_new(dap_enc_key_t *key);

void dap_enc_sig_picnic_key_delete(dap_enc_key_t *key);

void dap_enc_sig_picnic_update(dap_enc_key_t *key);

void dap_enc_sig_picnic_key_new_generate(dap_enc_key_t *key, const void *kex_buf, size_t kex_size,
        const void * seed, size_t seed_size,
        size_t key_size);

int dap_enc_sig_picnic_get_sign(dap_enc_key_t *a_key, const void *a_msg, const size_t a_msg_len,
        void *a_sig, size_t a_sig_len);

int dap_enc_sig_picnic_verify_sign(dap_enc_key_t *a_key, const void *a_msg, const size_t a_msg_len,
        void* a_sig, size_t a_sig_len);

uint64_t dap_enc_sig_picnic_deser_sig_size(const void *a_key);

#ifdef __cplusplus
}
#endif

