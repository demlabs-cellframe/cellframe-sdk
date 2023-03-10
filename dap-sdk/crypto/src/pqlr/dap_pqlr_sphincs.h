/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2023
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once
#include <stddef.h>

typedef struct dap_enc_key dap_enc_key_t;

void dap_pqlr_sphincs_key_new (dap_enc_key_t *a_key);
void dap_pqlr_sphincs_key_delete(dap_enc_key_t* a_key);
void dap_pqlr_sphincs_key_new_generate( dap_enc_key_t* a_key, const void* a_kex_buf, size_t a_kex_size,
                               const void* a_seed, size_t a_seed_size, size_t a_key_size);
size_t dap_pqlr_sphincs_create_sign(dap_enc_key_t* a_key, const void * a_msg, const size_t a_msg_size,
                  void* a_signature, const size_t a_signature_size);
size_t dap_pqlr_sphincs_verify_sign( dap_enc_key_t* a_key, const void* a_msg, const size_t a_msg_size, void* a_signature,
                     const size_t signature_size);

size_t dap_pqlr_sphincs_calc_signature_size(dap_enc_key_t* a_key);
