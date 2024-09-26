/*
 * Authors:
 * Frolov Daniil <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2020, All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <memory.h>
#include <assert.h>
#include "dap_tsd.h"
#include "dap_sign.h"
#include "dap_common.h"
#include "dap_enc_base58.h"
#include "dap_chain_datum_anchor.h"

#define LOG_TAG "dap_chain_datum_anchor"

int dap_chain_datum_anchor_get_hash_from_data(dap_chain_datum_anchor_t* a_anchor, dap_hash_fast_t *a_out_hash)
{
    dap_return_val_if_fail(a_anchor && a_out_hash, -1);
    dap_tsd_t *l_tsd = dap_tsd_find(a_anchor->data_n_sign, a_anchor->header.data_size, DAP_CHAIN_DATUM_ANCHOR_TSD_TYPE_DECREE_HASH);
    return l_tsd && l_tsd->size == sizeof(dap_hash_fast_t) ? ( _dap_tsd_get_scalar(l_tsd, a_out_hash), 0 ) : 1;
}

void dap_chain_datum_anchor_certs_dump(dap_string_t * a_str_out, byte_t * a_signs, size_t a_certs_size, const char *a_hash_out_type)
{
    dap_string_append_printf(a_str_out, "signatures: ");
    if (!a_certs_size) {
        dap_string_append_printf(a_str_out, "<NONE>\n");
        return;
    }

    dap_string_append_printf(a_str_out, "\n");

    size_t l_offset = 0;
    for (int i = 1; l_offset < (a_certs_size); i++) {
        dap_sign_t *l_sign = (dap_sign_t*)(a_signs + l_offset);
        l_offset += dap_sign_get_size(l_sign);
        if (l_sign->header.sign_size == 0) {
            dap_string_append_printf(a_str_out, "<CORRUPTED - 0 size signature>\n");
            continue;
        }

        dap_chain_hash_fast_t l_pkey_hash = {0};
        if (dap_sign_get_pkey_hash(l_sign, &l_pkey_hash) == false) {
            dap_string_append_printf(a_str_out, "<CORRUPTED - can't calc hash>\n");
            continue;
        }
        const char *l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                ? dap_enc_base58_encode_hash_to_str_static(&l_pkey_hash)
                : dap_chain_hash_fast_to_str_static(&l_pkey_hash);
        dap_string_append_printf(a_str_out, "%d) %s, %s, %u bytes\n", i, l_hash_str,
                                 dap_sign_type_to_str(l_sign->header.type), l_sign->header.sign_size);
    }
}

void dap_chain_datum_anchor_certs_dump_json(json_object * a_json_out, byte_t * a_signs, size_t a_certs_size, const char *a_hash_out_type)
{
    json_object_object_add(a_json_out, "signatures", json_object_new_string(""));
    if (!a_certs_size) {
        json_object_object_add(a_json_out, "Cert status", json_object_new_string("NONE"));
        return;
    }
    json_object* json_arr_certs_out = json_object_new_array();    
    size_t l_offset = 0;
    for (int i = 1; l_offset < (a_certs_size); i++) {
        json_object* json_obj_sign = json_object_new_object();
        dap_sign_t *l_sign = (dap_sign_t*)(a_signs + l_offset);
        l_offset += dap_sign_get_size(l_sign);
        if (l_sign->header.sign_size == 0) {
            json_object_object_add(json_obj_sign, "sign status", json_object_new_string("CORRUPTED - 0 size signature"));
            json_object_array_add(json_arr_certs_out, json_obj_sign);
            continue;
        }

        dap_chain_hash_fast_t l_pkey_hash = {0};
        if (dap_sign_get_pkey_hash(l_sign, &l_pkey_hash) == false) {
            json_object_object_add(json_obj_sign, "sign status", json_object_new_string("CORRUPTED - can't calc hash"));
            json_object_array_add(json_arr_certs_out, json_obj_sign);
            continue;
        }
        const char *l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                ? dap_enc_base58_encode_hash_to_str_static(&l_pkey_hash)
                : dap_chain_hash_fast_to_str_static(&l_pkey_hash);
        json_object_object_add(json_obj_sign, "sign #", json_object_new_uint64(i));
        json_object_object_add(json_obj_sign, "hash", json_object_new_string(l_hash_str));
        json_object_object_add(json_obj_sign, "type", json_object_new_string(dap_sign_type_to_str(l_sign->header.type)));
        json_object_object_add(json_obj_sign, "sign size", json_object_new_uint64(l_sign->header.sign_size));
        json_object_array_add(json_arr_certs_out, json_obj_sign); 
    }
    json_object_object_add(a_json_out,"SIGNS",json_arr_certs_out);
}

