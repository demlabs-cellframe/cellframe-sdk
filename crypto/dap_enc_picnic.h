/*
 * Authors:
 * Dmitriy A. Gearasimov <naeper@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

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
#include <stddef.h>

#include "dap_enc_key.h"

#define DAP_ENC_KEY_TYPE_PICNIC(a) ((dap_enc_picnic_key_t *)((a)->_inheritor))

void dap_enc_picnic_key_new(dap_enc_key_t* a_key);
void dap_enc_picnic_key_generate(dap_enc_key_t * a_key, const void* a_seed, size_t a_seed_size,
                                size_t a_key_size);

void dap_enc_picnic_key_make_public(dap_enc_key_t * a_key, void * a_key_raw, const size_t a_key_size);
void dap_enc_picnic_key_make_public_inside(dap_enc_key_t * a_key); // saves public part inside the dap_enc_picnic_key_t

void dap_enc_picnic_key_new_from_raw_public(dap_enc_key_t* a_key, const void * a_in, size_t a_in_size);
void dap_enc_picnic_key_new_from_raw_private(dap_enc_key_t* a_key, const void * a_in, size_t a_in_size);
void dap_enc_picnic_key_delete(dap_enc_key_t * a_key);

size_t dap_enc_picnic_enc_na(dap_enc_key_t* b_key, const void *a_buf_in, const size_t a_buf_in_size,
                             void * a_buf_out, const size_t a_buf_out_size_max);
size_t dap_enc_picnic_dec_na(dap_enc_key_t* b_key, const void *a_buf_in, const size_t a_buf_in_size,
                             void * a_buf_out, const size_t a_buf_out_size_max);
