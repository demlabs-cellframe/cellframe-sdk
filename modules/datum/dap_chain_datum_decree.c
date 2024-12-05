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
#include "dap_chain_datum_decree.h"
#include "dap_enc_base58.h"
#include "dap_chain_common.h"
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
    dap_list_t *l_ret = dap_tsd_find_all(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER);
    if (a_owners_num)
        *a_owners_num = (uint16_t)dap_list_length(l_ret);
    return l_ret;
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

int dap_chain_datum_decree_get_stake_signer_node_addr(dap_chain_datum_decree_t *a_decree, dap_chain_node_addr_t *a_node_addr)
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

void dap_chain_datum_decree_dump_json(json_object *a_json_out, dap_chain_datum_decree_t *a_decree, size_t a_decree_size, const char *a_hash_out_type)
{
    char *l_type_str;
    switch(a_decree->header.type)
    {
        case DAP_CHAIN_DATUM_DECREE_TYPE_COMMON:
            l_type_str = "DECREE_TYPE_COMMON";
            break;
        case DAP_CHAIN_DATUM_DECREE_TYPE_SERVICE:
            l_type_str = "DECREE_TYPE_SERVICE";
            break;
        default:
            l_type_str = "DECREE_TYPE_UNKNOWN";
    }
    json_object_object_add(a_json_out, "type", json_object_new_string(l_type_str));
    const char *l_subtype_str = dap_chain_datum_decree_subtype_to_str(a_decree->header.sub_type);
    json_object_object_add(a_json_out, "subtype", json_object_new_string(l_subtype_str));
    json_object_object_add(a_json_out, "TSD", json_object_new_string(""));
    dap_tsd_t *l_tsd; size_t l_tsd_size;
    dap_tsd_iter(l_tsd, l_tsd_size, a_decree->data_n_signs, a_decree->header.data_size) {
        switch(l_tsd->type) {
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_VALUE:
            if (l_tsd->size > sizeof(uint256_t)){
                json_object_object_add(a_json_out, "Value", json_object_new_string("WRONG SIZE"));
                break;
            }
            uint256_t l_value = uint256_0;
            _dap_tsd_get_scalar(l_tsd, &l_value);
            const char *l_value_str = dap_uint256_to_char(l_value, NULL);
            json_object_object_add(a_json_out, "Value", json_object_new_string(l_value_str));
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGN:
        break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE:
            if (l_tsd->size > sizeof(uint256_t)){
                json_object_object_add(a_json_out, "Fee", json_object_new_string("WRONG SIZE"));
                break;
            }
            uint256_t l_fee_value = uint256_0;
            _dap_tsd_get_scalar(l_tsd, &l_fee_value);
            const char *l_fee_value_str = dap_uint256_to_char(l_fee_value, NULL);
            json_object_object_add(a_json_out, "Fee", json_object_new_string(l_fee_value_str));
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER:
            if (l_tsd->size < sizeof(dap_pkey_t)) {
                json_object_object_add(a_json_out, "Owner fingerprint", json_object_new_string("WRONG SIZE"));
                break;
            }
            dap_pkey_t *l_owner_pkey = /*DAP_NEW_STACK_SIZE(dap_pkey_t, l_tsd->size);
            memcpy(l_owner_pkey, l_tsd->data, l_tsd->size);*/ _dap_tsd_get_object(l_tsd, dap_pkey_t);
            json_object_object_add(a_json_out, "Owner fingerprint", json_object_new_string(dap_get_data_hash_str(l_owner_pkey->pkey, l_owner_pkey->header.size).s));
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER:
            if (l_tsd->size > sizeof(uint256_t)){
                json_object_object_add(a_json_out, "Owner min", json_object_new_string("WRONG SIZE"));
                break;
            }
            uint256_t l_owner_min = uint256_0;
            _dap_tsd_get_scalar(l_tsd, &l_owner_min);
            const char *l_owner_min_str = dap_uint256_to_char(l_owner_min, NULL);
            json_object_object_add(a_json_out, "Owner min", json_object_new_string(l_owner_min_str));
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE_WALLET:
            if (l_tsd->size > sizeof(dap_chain_addr_t)) {
                json_object_object_add(a_json_out, "Wallet for fee", json_object_new_string("WRONG SIZE"));
                break;
            }
            dap_chain_addr_t *l_addr_fee_wallet = /*{ };
            _dap_tsd_get_scalar(l_tsd, &l_addr_fee_wallet);*/ _dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            json_object_object_add(a_json_out, "Wallet for fee", json_object_new_string(dap_chain_addr_to_str_static(l_addr_fee_wallet)));
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HASH:
            if (l_tsd->size > sizeof(dap_hash_fast_t)) {
                json_object_object_add(a_json_out, "Stake tx", json_object_new_string("WRONG SIZE"));
                break;
            }
            dap_hash_fast_t *l_stake_tx = /*{ };
            _dap_tsd_get_scalar(l_tsd, &l_stake_tx);*/ _dap_tsd_get_object(l_tsd, dap_hash_fast_t);
            const char *l_stake_tx_hash = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str_static(l_stake_tx)
                    : dap_chain_hash_fast_to_str_static(l_stake_tx);
            json_object_object_add(a_json_out, "Stake tx", json_object_new_string(l_stake_tx_hash));
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_VALUE:
            if (l_tsd->size > sizeof(uint256_t)){
                json_object_object_add(a_json_out, "Stake value", json_object_new_string("WRONG SIZE"));
                break;
            }
            uint256_t l_stake_value = uint256_0;
            _dap_tsd_get_scalar(l_tsd, &l_stake_value);
            const char *l_stake_value_str = dap_uint256_to_char(l_stake_value, NULL);
            json_object_object_add(a_json_out, "Stake value", json_object_new_string(l_stake_value_str));
            break;
       case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNING_ADDR:
            if (l_tsd->size > sizeof(dap_chain_addr_t)) {
                json_object_object_add(a_json_out, "Signing addr", json_object_new_string("WRONG SIZE"));
                break;
            }
            dap_chain_addr_t *l_stake_addr_signing = /*{ };
            _dap_tsd_get_scalar(l_tsd, &l_stake_addr_signing);*/ _dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            json_object_object_add(a_json_out, "Signing addr", json_object_new_string(dap_chain_addr_to_str_static(l_stake_addr_signing)));
            dap_chain_hash_fast_t l_pkey_signing = l_stake_addr_signing->data.hash_fast;
            const char *l_pkey_signing_str = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str_static(&l_pkey_signing)
                    : dap_chain_hash_fast_to_str_static(&l_pkey_signing);
            json_object_object_add(a_json_out, "Signing pkey fingerprint", json_object_new_string(l_pkey_signing_str));
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_NODE_ADDR:
            if(l_tsd->size > sizeof(dap_chain_node_addr_t)){
                json_object_object_add(a_json_out, "Node addr", json_object_new_string("WRONG SIZE"));
                break;
            }
            dap_chain_node_addr_t *l_node_addr = _dap_tsd_get_object(l_tsd, dap_chain_node_addr_t);
            char l_buf[24];
            snprintf(l_buf, sizeof(l_buf), NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS(l_node_addr));
            json_object_object_add(a_json_out, "Node addr", json_object_new_string(l_buf));
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_VALUE:
            if (l_tsd->size > sizeof(uint256_t)) {
                json_object_object_add(a_json_out, "Min value", json_object_new_string("WRONG SIZE"));
                break;
            }
            uint256_t l_min_value = uint256_0;
            _dap_tsd_get_scalar(l_tsd, &l_min_value);
            const char *l_min_value_str = dap_uint256_to_char(l_min_value, NULL);
            json_object_object_add(a_json_out, "Min value", json_object_new_string(l_min_value_str));
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_SIGNERS_COUNT:
            if (l_tsd->size > sizeof(uint256_t)) {
                json_object_object_add(a_json_out, "Min signers count", json_object_new_string("WRONG SIZE"));
                break;
            }
            uint256_t l_min_signers_count = uint256_0;
            _dap_tsd_get_scalar(l_tsd, &l_min_signers_count);
            const char *l_min_signers_count_str = dap_uint256_to_char(l_min_signers_count, NULL);
            json_object_object_add(a_json_out, "Min signers count", json_object_new_string(l_min_signers_count_str));
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HOST:
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STRING:
            json_object_object_add(a_json_out, "Host address", json_object_new_string(dap_tsd_get_string(l_tsd)));
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_ACTION:
            if (l_tsd->size != sizeof(uint8_t)) {
                json_object_object_add(a_json_out, "Action", json_object_new_string("WRONG SIZE"));
                break;
            }
            uint8_t l_action = 0;
            _dap_tsd_get_scalar(l_tsd, &l_action);
            json_object_object_add(a_json_out, "tAction", l_action ?
                                        json_object_new_string("add (enable)") : json_object_new_string("delete (disable)"));
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGNATURE_TYPE:
            if (l_tsd->size != sizeof(uint32_t)) {
                json_object_object_add(a_json_out, "Signature type", json_object_new_string("WRONG SIZE"));
                break;
            }
            uint32_t l_type = 0;
            _dap_tsd_get_scalar(l_tsd, &l_type);
            dap_sign_type_t l_sign_type = { .type = l_type };
            json_object_object_add(a_json_out, "Signature type", json_object_new_string(dap_sign_type_to_str(l_sign_type)));
            break;
        default:
            json_object_object_add(a_json_out, "UNKNOWN_TYPE_TSD_SECTION", json_object_new_string(""));
            break;
        }
    }
    dap_chain_datum_decree_certs_dump_json(a_json_out, a_decree->data_n_signs + a_decree->header.data_size,
                                      a_decree->header.signs_size, a_hash_out_type);
}

void dap_chain_datum_decree_certs_dump_json(json_object * a_json_out, byte_t * a_signs, size_t a_certs_size, const char *a_hash_out_type)
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
        dap_sign_t *l_sign = (dap_sign_t *) (a_signs + l_offset);
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
    json_object_object_add(a_json_out,"SIGNS", json_arr_certs_out);
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
        dap_sign_t * l_sign = dap_cert_sign(a_certs[i], a_datum_decree,
                                            sizeof(dap_chain_datum_decree_t) + a_datum_decree->header.data_size, 0);
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
