/*
 * Authors:
 * Frolov Daniil <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2020, All rights reserved.
 *
 * This file is part of CellFrame SDK the open source project
 *
 *    CellFrame SDK is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    CellFrame SDK is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <memory.h>
#include <assert.h>
#include "dap_tsd.h"
#include "dap_sign.h"
#include "dap_common.h"
#include "dap_chain_datum_decree.h"
#include "dap_enc_base58.h"
#include "dap_chain_common.h"
#include "dap_json.h"
#ifdef DAP_OS_UNIX
#include <arpa/inet.h>
#endif
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif


#define LOG_TAG "dap_chain_datum_decree"

dap_sign_t *dap_chain_datum_decree_get_signs(dap_chain_datum_decree_t *a_decree, size_t* a_signs_size)
{
    dap_return_val_if_fail(a_decree && a_signs_size, NULL);
    dap_sign_t *l_signs_section = (dap_sign_t*)(a_decree->data_n_signs + a_decree->header.data_size);
    *a_signs_size = a_decree->header.signs_size;
    return l_signs_section;
}

static bool s_find_pkey(dap_chain_datum_decree_t *a_decree, dap_pkey_t *a_pkey)
{
    dap_return_val_if_pass(!a_decree || !a_pkey || !a_pkey->header.size, false);
    dap_sign_t *l_signs_section = (dap_sign_t*)(a_decree->data_n_signs + a_decree->header.data_size);
    size_t l_sign_size = 0;
    bool l_ret = false;
    for (uint64_t l_offset = 0; !l_ret && l_offset + sizeof(dap_sign_t) < a_decree->header.signs_size; l_offset += l_sign_size) {
        dap_sign_t *l_sign = (dap_sign_t *)(a_decree->data_n_signs + a_decree->header.data_size + l_offset);
        l_sign_size = dap_sign_get_size(l_sign);
        if (l_offset + l_sign_size <= l_offset || l_offset + l_sign_size > a_decree->header.signs_size)
            break;
        size_t l_pkey_ser_size = 0;
        const uint8_t *l_pkey_ser = dap_sign_get_pkey(l_sign, &l_pkey_ser_size);
        l_ret = (l_pkey_ser_size == a_pkey->header.size) && !memcmp(l_pkey_ser, a_pkey->pkey, l_pkey_ser_size);
    }
    return l_ret;
}

int dap_chain_datum_decree_get_fee(dap_chain_datum_decree_t *a_decree, uint256_t *a_fee_value)
{
    dap_return_val_if_fail(a_decree && a_fee_value, -1);
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE);
    return l_tsd && l_tsd->size == sizeof(uint256_t) ? ( _dap_tsd_get_scalar(l_tsd, a_fee_value), 0 ) : 1;
}

int dap_chain_datum_decree_get_value(dap_chain_datum_decree_t *a_decree, uint256_t *a_value)
{
    dap_return_val_if_fail(a_decree && a_value, -1);
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_VALUE);
    return l_tsd && l_tsd->size == sizeof(uint256_t) ? ( _dap_tsd_get_scalar(l_tsd, a_value), 0 ) : 1;
}

int dap_chain_datum_decree_get_fee_addr(dap_chain_datum_decree_t *a_decree, dap_chain_addr_t *a_fee_wallet)
{
    dap_return_val_if_fail(a_decree && a_fee_wallet, -1);
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE_WALLET);
    return l_tsd && l_tsd->size == sizeof(dap_chain_addr_t) ? ( _dap_tsd_get_scalar(l_tsd, a_fee_wallet), 0 ) : 1;
}

dap_list_t *dap_chain_datum_decree_get_owners(dap_chain_datum_decree_t *a_decree, uint16_t *a_owners_num)
{
    dap_return_val_if_fail(a_decree && a_owners_num, NULL);
    dap_list_t *l_ret = dap_tsd_find_all(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER, 0);
    dap_list_t *it, *tmp;
    DL_FOREACH_SAFE(l_ret, it, tmp) {
        dap_tsd_t *l_tsd = it->data;
        if (l_tsd->size < sizeof(dap_pkey_t) || l_tsd->size != sizeof(dap_pkey_t) + ((dap_pkey_t *)l_tsd->data)->header.size) {
            log_it(L_ERROR, "Incorrect size %u of owner pkey", l_tsd->size);
            DL_DELETE(l_ret, it);
            DAP_DEL_MULTY(it->data, it);
        }
    }
    if (a_owners_num)
        *a_owners_num = (uint16_t)dap_list_length(l_ret);
    return l_ret;
}

int dap_chain_datum_decree_get_hardfork_changed_addrs(dap_chain_datum_decree_t *a_decree, dap_json_t **a_json_obj)
{
    dap_return_val_if_fail(a_decree && a_json_obj, -1);
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HARDFORK_CHANGED_ADDRS);
    return l_tsd ? (!dap_strcmp(dap_tsd_get_string_const(l_tsd), DAP_TSD_CORRUPTED_STRING) ? (*a_json_obj = dap_json_parse_string(dap_tsd_get_string_const(l_tsd)), 0) :  1)  : 1;
}

int dap_chain_datum_decree_get_min_owners(dap_chain_datum_decree_t *a_decree, uint256_t *a_min_owners_num)
{
    dap_return_val_if_fail(a_decree && a_min_owners_num, -1);
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER);
    return l_tsd && l_tsd->size == sizeof(uint256_t) ? ( _dap_tsd_get_scalar(l_tsd, a_min_owners_num), 0 ) : 1;
}

int dap_chain_datum_decree_get_hash(dap_chain_datum_decree_t *a_decree, dap_hash_fast_t *a_tx_hash)
{
    dap_return_val_if_fail(a_decree && a_tx_hash, -1);
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HASH);
    return l_tsd && l_tsd->size == sizeof(dap_hash_fast_t) ? ( _dap_tsd_get_scalar(l_tsd, a_tx_hash), 0 ) : 1;
}

int dap_chain_datum_decree_get_stake_value(dap_chain_datum_decree_t *a_decree, uint256_t *a_stake_value)
{
    dap_return_val_if_fail(a_decree && a_stake_value, -1);
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_VALUE);
    return l_tsd && l_tsd->size == sizeof(uint256_t) ? ( _dap_tsd_get_scalar(l_tsd, a_stake_value), 0 ) : 1;
}

int dap_chain_datum_decree_get_stake_signing_addr(dap_chain_datum_decree_t *a_decree, dap_chain_addr_t *a_signing_addr)
{
    dap_return_val_if_fail(a_decree && a_signing_addr, -1);
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNING_ADDR);
    return l_tsd && l_tsd->size == sizeof(dap_chain_addr_t) ? ( _dap_tsd_get_scalar(l_tsd, a_signing_addr), 0 ) : 1;
}

int dap_chain_datum_decree_get_node_addr(dap_chain_datum_decree_t *a_decree, dap_chain_node_addr_t *a_node_addr)
{
    dap_return_val_if_fail(a_decree && a_node_addr, -1);
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_NODE_ADDR);
    return l_tsd && l_tsd->size == sizeof(dap_chain_node_addr_t) ? ( _dap_tsd_get_scalar(l_tsd, a_node_addr), 0 ) : 1;
}

int dap_chain_datum_decree_get_stake_min_value(dap_chain_datum_decree_t *a_decree, uint256_t *a_min_value)
{
    dap_return_val_if_fail(a_decree && a_min_value, -1);
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_VALUE);
    return l_tsd && l_tsd->size == sizeof(uint256_t) ? ( _dap_tsd_get_scalar(l_tsd, a_min_value), 0 ) : 1;
}

int dap_chain_datum_decree_get_stake_min_signers_count(dap_chain_datum_decree_t *a_decree, uint256_t *a_min_signers_count)
{
    dap_return_val_if_fail(a_decree && a_min_signers_count, -1);
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_SIGNERS_COUNT);
    return l_tsd && l_tsd->size == sizeof(uint256_t) ? ( _dap_tsd_get_scalar(l_tsd, a_min_signers_count), 0 ) : 1;
}

int dap_chain_datum_decree_get_action(dap_chain_datum_decree_t *a_decree, uint8_t *a_action)
{
    dap_return_val_if_fail(a_decree && a_action, -1);
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_ACTION);
    return l_tsd && l_tsd->size == sizeof(uint8_t) ? ( _dap_tsd_get_scalar(l_tsd, a_action), 0 ) : 1;
}

int dap_chain_datum_decree_get_signature_type(dap_chain_datum_decree_t *a_decree, uint32_t *a_signature_type)
{
    dap_return_val_if_fail(a_decree && a_signature_type, -1);
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGNATURE_TYPE);
    return l_tsd && l_tsd->size == sizeof(uint32_t) ? ( _dap_tsd_get_scalar(l_tsd, a_signature_type), 0 ) : 1;
}

int dap_chain_datum_decree_get_ban_addr(dap_chain_datum_decree_t *a_decree, const char **a_addr)
{
    dap_return_val_if_fail(a_decree && a_addr, -1);
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HOST);
    if (!l_tsd)
        l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STRING);
    return l_tsd ? ( *a_addr = dap_tsd_get_string_const(l_tsd), !dap_strcmp(*a_addr, DAP_TSD_CORRUPTED_STRING) ) : 1;
}

int dap_chain_datum_decree_get_atom_num(dap_chain_datum_decree_t *a_decree, uint64_t *a_atom_num)
{
    dap_return_val_if_fail(a_decree && a_atom_num, -1);
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_BLOCK_NUM);
    return l_tsd && l_tsd->size == sizeof(uint64_t) ? ( _dap_tsd_get_scalar(l_tsd, a_atom_num), 0 ) : 1;
}

dap_pkey_t *dap_chain_datum_decree_get_pkey(dap_chain_datum_decree_t *a_decree)
{
    dap_return_val_if_fail(a_decree, NULL);
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_PKEY);
    return (l_tsd && dap_pkey_get_size((dap_pkey_t *)l_tsd->data) == l_tsd->size) ? (dap_pkey_t *)l_tsd->data : NULL;
}


/* dap_chain_datum_decree_get_policy moved to chain module due to circular dependency */


int dap_chain_datum_decree_get_empty_block_every_times(dap_chain_datum_decree_t *a_decree, uint16_t *a_blockgen_period)
{
    dap_return_val_if_fail(a_decree && a_blockgen_period, -1);
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_BLOCKGEN_PERIOD);
    return l_tsd && l_tsd->size == sizeof(uint16_t) ? ( _dap_tsd_get_scalar(l_tsd, a_blockgen_period), 0 ) : 1;
}

void dap_chain_datum_decree_certs_dump_json(dap_json_t *a_json_out, byte_t *a_signs, size_t a_certs_size, const char *a_hash_out_type, int a_version)
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
        dap_sign_t *l_sign = (dap_sign_t *) (a_signs + l_offset);
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

dap_chain_datum_decree_t *dap_chain_datum_decree_new(dap_chain_net_id_t a_net_id, dap_chain_id_t a_chain_id,
                                                     dap_chain_cell_id_t a_cell_id, size_t a_total_tsd_size)
{
    dap_chain_datum_decree_t *l_decree = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_datum_decree_t, sizeof(dap_chain_datum_decree_t) + a_total_tsd_size, NULL);

    l_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
    l_decree->header.ts_created = dap_time_now();
    l_decree->header.type = DAP_CHAIN_DATUM_DECREE_TYPE_COMMON;
    l_decree->header.common_decree_params.net_id = a_net_id;
    l_decree->header.common_decree_params.chain_id = a_chain_id;
    l_decree->header.common_decree_params.cell_id = a_cell_id;
    l_decree->header.data_size = a_total_tsd_size;
    return l_decree;
}

dap_chain_datum_decree_t *dap_chain_datum_decree_sign_in_cycle(dap_cert_t **a_certs, dap_chain_datum_decree_t *a_datum_decree,
                                                  size_t a_certs_count, size_t *a_total_sign_count)
{
    size_t l_cur_sign_offset = a_datum_decree->header.data_size + a_datum_decree->header.signs_size;
    size_t l_total_signs_size = a_datum_decree->header.signs_size, l_total_sign_count = 0;
    for(size_t i = 0; i < a_certs_count; i++) {
        dap_pkey_t *l_cur_pkey = dap_cert_to_pkey(a_certs[i]);
        if (s_find_pkey(a_datum_decree, l_cur_pkey)) {
            dap_chain_hash_fast_t l_pkey_hash = { };
            dap_pkey_get_hash(l_cur_pkey, &l_pkey_hash);
            log_it(L_ERROR, "Sign with %s pkey already exist in decree", dap_hash_fast_to_str_static(&l_pkey_hash));
            DAP_DELETE(l_cur_pkey);
            continue;;
        }
        DAP_DELETE(l_cur_pkey);
        dap_sign_t *l_sign = dap_cert_sign(a_certs[i], a_datum_decree,
                                            sizeof(dap_chain_datum_decree_t) + a_datum_decree->header.data_size);
        if (!l_sign) {
            log_it(L_ERROR, "Decree signing failed");
            DAP_DELETE(a_datum_decree);
            return NULL;
        }
        size_t l_sign_size = dap_sign_get_size(l_sign);
        dap_chain_datum_decree_t *l_datum_decree = DAP_REALLOC_RET_VAL_IF_FAIL(
            a_datum_decree, sizeof(dap_chain_datum_decree_t) + l_cur_sign_offset + l_sign_size, NULL, l_sign);
        a_datum_decree = l_datum_decree;
        memcpy(a_datum_decree->data_n_signs + l_cur_sign_offset, l_sign, l_sign_size);
        DAP_DELETE(l_sign);
        l_total_signs_size += l_sign_size;
        l_cur_sign_offset += l_sign_size;
        a_datum_decree->header.signs_size = l_total_signs_size;
        log_it(L_DEBUG,"<-- Signed with '%s'", a_certs[i]->name);
        l_total_sign_count++;
    }
    if (a_total_sign_count)
        *a_total_sign_count = l_total_sign_count;
    return a_datum_decree;
}
