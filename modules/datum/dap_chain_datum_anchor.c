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
#include "dap_json.h"
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

void dap_chain_datum_anchor_certs_dump_json(dap_json_t *a_json_out, byte_t *a_signs, size_t a_certs_size, const char *a_hash_out_type, int a_version)
{
    if (a_version == 1)
        dap_json_object_add_string(a_json_out, "signatures", "");
    if (!a_certs_size) {
        dap_json_object_add_string(a_json_out, a_version == 1 ? "Cert status" : "cert_status", "NONE");
        return;
    }
    dap_json_t *json_arr_certs_out = dap_json_array_new();    
    size_t l_offset = 0;
    for (int i = 1; l_offset < (a_certs_size); i++) {
        dap_json_t *json_obj_sign = dap_json_object_new();
        dap_sign_t *l_sign = (dap_sign_t*)(a_signs + l_offset);
        l_offset += dap_sign_get_size(l_sign);
        if (l_sign->header.sign_size == 0) {
            dap_json_object_add_string(json_obj_sign, a_version == 1 ? "sign status" : "sig_status", "CORRUPTED - 0 size signature");
            dap_json_array_add(json_arr_certs_out, json_obj_sign);
            continue;
        }

        dap_chain_hash_fast_t l_pkey_hash = {0};
        if (dap_sign_get_pkey_hash(l_sign, &l_pkey_hash) == false) {
            dap_json_object_add_string(json_obj_sign, a_version == 1 ? "sign status" : "sig_status", "CORRUPTED - can't calc hash");
            dap_json_array_add(json_arr_certs_out, json_obj_sign);
            continue;
        }
        const char *l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                ? dap_enc_base58_encode_hash_to_str_static(&l_pkey_hash)
                : dap_chain_hash_fast_to_str_static(&l_pkey_hash);
        dap_json_object_add_uint64(json_obj_sign, a_version == 1 ? "sign #" : "sig_num", i);
        dap_json_object_add_string(json_obj_sign, a_version == 1 ? "hash" : "sig_pkey_hash", l_hash_str);
        dap_json_object_add_string(json_obj_sign, a_version == 1 ? "type" : "sig_type", dap_sign_type_to_str(l_sign->header.type));
        dap_json_object_add_uint64(json_obj_sign, a_version == 1 ? "sign size" : "sig_size", l_sign->header.sign_size);
        dap_json_array_add(json_arr_certs_out, json_obj_sign); 
    }
    dap_json_object_add_object(a_json_out, a_version == 1 ? "SIGNS" : "signs", json_arr_certs_out);
}

