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


#define LOG_TAG "dap_chain_datum_decree"



dap_sign_t *dap_chain_datum_decree_get_signs(dap_chain_datum_decree_t *a_decree, size_t* a_signs_size)
{
    if (!a_decree || !a_signs_size) {
        log_it(L_CRITICAL, "Invalid arguments");
        return NULL;
    }

    dap_sign_t *l_signs_section = (dap_sign_t*)(a_decree->data_n_signs + a_decree->header.data_size);
    *a_signs_size = a_decree->header.signs_size;
    return l_signs_section;
}

int dap_chain_datum_decree_get_fee(dap_chain_datum_decree_t *a_decree, uint256_t *a_fee_value)
{
    if(!a_decree || !a_fee_value) {
        log_it(L_CRITICAL, "Invalid arguments");
        return -1;
    }
    dap_tsd_t* l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE);
    return l_tsd ? ({ _dap_tsd_get_scalar(l_tsd, a_fee_value); 0; }) : 1;
}

int dap_chain_datum_decree_get_value(dap_chain_datum_decree_t *a_decree, uint256_t *a_value)
{
    dap_return_val_if_fail(a_decree && a_value, -1);
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_VALUE);
    return l_tsd ? ({ _dap_tsd_get_scalar(l_tsd, a_value); 0; }) : 1;
}

int dap_chain_datum_decree_get_fee_addr(dap_chain_datum_decree_t *a_decree, dap_chain_addr_t *a_fee_wallet)
{
    if(!a_decree || !a_fee_wallet) {
        log_it(L_CRITICAL, "Invalid arguments");
        return -1;
    }
    dap_tsd_t* l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE_WALLET);
    return l_tsd ? ({ _dap_tsd_get_scalar(l_tsd, a_fee_wallet); 0; }) : 1;
}

static void *s_cb_copy_pkeys(const void *a_pkey, UNUSED_ARG void *a_data) {
    return DAP_DUP((dap_pkey_t*)a_pkey);
}

dap_list_t *dap_chain_datum_decree_get_owners(dap_chain_datum_decree_t *a_decree, uint16_t *a_owners_num)
{
    if(!a_decree || !a_owners_num){
        log_it(L_CRITICAL, "Invalid arguments");
        return NULL;
    }
    dap_list_t *l_tsd_list = dap_tsd_find_all(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER);
    *a_owners_num = (uint16_t)dap_list_length(l_tsd_list);
    dap_list_t *l_ret = dap_list_copy_deep(l_tsd_list, s_cb_copy_pkeys, NULL);
    dap_list_free(l_tsd_list);
    return l_ret;
}

int dap_chain_datum_decree_get_min_owners(dap_chain_datum_decree_t *a_decree, uint16_t *a_min_owners_num)
{
    if(!a_decree || !a_min_owners_num){
        log_it(L_CRITICAL, "Invalid arguments");
        return -1;
    }
    dap_tsd_t* l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER);
    return l_tsd ? ({ _dap_tsd_get_scalar(l_tsd, a_min_owners_num); 0; }) : 1;
}

int dap_chain_datum_decree_get_stake_tx_hash(dap_chain_datum_decree_t *a_decree, dap_hash_fast_t *a_tx_hash)
{
    if(!a_decree || !a_tx_hash){
        log_it(L_CRITICAL, "Invalid arguments");
        return -1;
    }
    dap_tsd_t* l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_TX_HASH);
    return l_tsd ? ({ _dap_tsd_get_scalar(l_tsd, a_tx_hash); 0; }) : 1;
}

int dap_chain_datum_decree_get_stake_value(dap_chain_datum_decree_t *a_decree, uint256_t *a_stake_value)
{
    if(!a_decree || !a_stake_value){
        log_it(L_CRITICAL, "Invalid arguments");
        return -1;
    }
    dap_tsd_t* l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_VALUE);
    return l_tsd ? ({ _dap_tsd_get_scalar(l_tsd, a_stake_value); 0; }) : 1;
}

int dap_chain_datum_decree_get_stake_signing_addr(dap_chain_datum_decree_t *a_decree, dap_chain_addr_t *a_signing_addr)
{
    if(!a_decree || !a_signing_addr){
        log_it(L_CRITICAL, "Invalid arguments");
        return -1;
    }
    dap_tsd_t* l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNING_ADDR);
    return l_tsd ? ({ _dap_tsd_get_scalar(l_tsd, a_signing_addr); 0; }) : 1;
}

int dap_chain_datum_decree_get_stake_signer_node_addr(dap_chain_datum_decree_t *a_decree, dap_chain_node_addr_t *a_node_addr)
{
    if(!a_decree || !a_node_addr){
        log_it(L_CRITICAL, "Invalid arguments");
        return -1;
    }
    dap_tsd_t* l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNER_NODE_ADDR);
    return l_tsd ? ({ _dap_tsd_get_scalar(l_tsd, a_node_addr); 0; }) : 1;
}

int dap_chain_datum_decree_get_stake_min_value(dap_chain_datum_decree_t *a_decree, uint256_t *a_min_value)
{
    if(!a_decree || !a_min_value){
        log_it(L_CRITICAL, "Invalid arguments");
        return -1;
    }
    dap_tsd_t* l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_VALUE);
    return l_tsd ? ({ _dap_tsd_get_scalar(l_tsd, a_min_value); 0; }) : 1;
}

int dap_chain_datum_decree_get_stake_min_signers_count(dap_chain_datum_decree_t *a_decree, uint256_t *a_min_signers_count)
{
    if(!a_decree || !a_min_signers_count){
        log_it(L_CRITICAL, "Invalid arguments");
        return -1;
    }
    dap_tsd_t* l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_SIGNERS_COUNT);
    return l_tsd ? ({ _dap_tsd_get_scalar(l_tsd, a_min_signers_count); 0; }) : 1;
}

void dap_chain_datum_decree_dump(dap_string_t *a_str_out, dap_chain_datum_decree_t *a_decree, size_t a_decree_size, const char *a_hash_out_type) {
    char *l_type_str = "";
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
    dap_string_append_printf(a_str_out, "type: %s\n", l_type_str);
    const char *l_subtype_str = dap_chain_datum_decree_subtype_to_str(a_decree->header.sub_type);
    dap_string_append_printf(a_str_out, "subtype: %s\n", l_subtype_str);
    dap_string_append_printf(a_str_out, "TSD:\n");
    for (size_t l_offset = 0; l_offset < a_decree->header.data_size;) {
        dap_tsd_t *l_tsd = (dap_tsd_t *)((byte_t*)a_decree->data_n_signs + l_offset);
        l_offset += dap_tsd_size(l_tsd);
        switch(l_tsd->type) {
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_VALUE:
                if (l_tsd->size > sizeof(uint256_t)){
                    dap_string_append_printf(a_str_out, "\tValue: <WRONG SIZE>\n");
                    break;
                }
                uint256_t l_value = uint256_0;
                _dap_tsd_get_scalar(l_tsd, &l_value);
                dap_string_append_printf(a_str_out, "\tValue: %s\n", dap_chain_balance_print(l_value));
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGN:
            break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE:
                if (l_tsd->size > sizeof(uint256_t)){
                    dap_string_append_printf(a_str_out, "\tFee: <WRONG SIZE>\n");
                    break;
                }
                uint256_t l_fee_value = uint256_0;
                _dap_tsd_get_scalar(l_tsd, &l_fee_value);
                dap_string_append_printf(a_str_out, "\tFee: %s\n", dap_chain_balance_print(l_fee_value));
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER:
                if (l_tsd->size < sizeof(dap_pkey_t)) {
                    dap_string_append_printf(a_str_out, "\tOwner fingerprint: <WRONG SIZE>\n");
                    break;
                }
                dap_pkey_t *l_owner_pkey = /*DAP_NEW_STACK_SIZE(dap_pkey_t, l_tsd->size);
                memcpy(l_owner_pkey, l_tsd->data, l_tsd->size);*/ _dap_tsd_get_object(l_tsd, dap_pkey_t);
                char *l_owner_pkey_str;
                dap_get_data_hash_str_static(l_owner_pkey->pkey, l_owner_pkey->header.size, l_owner_pkey_str);
                dap_string_append_printf(a_str_out, "\tOwner fingerprint: %s\n", l_owner_pkey_str);
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER:
                if (l_tsd->size > sizeof(uint256_t)){
                    dap_string_append_printf(a_str_out, "\tOwner min: <WRONG SIZE>\n");
                    break;
                }
                uint256_t l_owner_min = uint256_0;
                _dap_tsd_get_scalar(l_tsd, &l_owner_min);
                dap_string_append_printf(a_str_out, "\tOwner min: %s\n", dap_chain_balance_print(l_owner_min));
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE_WALLET:
                if (l_tsd->size > sizeof(dap_chain_addr_t)) {
                    dap_string_append_printf(a_str_out, "\tWallet for fee: <WRONG SIZE>\n");
                    break;
                }
                dap_chain_addr_t *l_addr_fee_wallet = /*{ };
                _dap_tsd_get_scalar(l_tsd, &l_addr_fee_wallet);*/ _dap_tsd_get_object(l_tsd, dap_chain_addr_t);
                dap_string_append_printf(a_str_out, "\tWallet for fee: %s\n", dap_chain_addr_to_str(l_addr_fee_wallet));
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_TX_HASH:
                if (l_tsd->size > sizeof(dap_hash_fast_t)) {
                    dap_string_append_printf(a_str_out, "\tStake tx: <WRONG SIZE>\n");
                    break;
                }
                dap_hash_fast_t *l_stake_tx = /*{ };
                _dap_tsd_get_scalar(l_tsd, &l_stake_tx);*/ _dap_tsd_get_object(l_tsd, dap_hash_fast_t);
                char l_stake_tx_hash[DAP_HASH_FAST_STR_SIZE];
                dap_strcmp(a_hash_out_type, "hex")
                        ? (int)dap_enc_base58_encode(l_stake_tx, sizeof(l_stake_tx), l_stake_tx_hash)
                        : dap_chain_hash_fast_to_str(l_stake_tx, l_stake_tx_hash, sizeof(l_stake_tx_hash));
                dap_string_append_printf(a_str_out, "\tStake tx: %s\n", l_stake_tx_hash);
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_VALUE:
                if (l_tsd->size > sizeof(uint256_t)){
                    dap_string_append_printf(a_str_out, "\tStake value: <WRONG SIZE>\n");
                    break;
                }
                uint256_t l_stake_value = uint256_0;
                _dap_tsd_get_scalar(l_tsd, &l_stake_value);
                dap_string_append_printf(a_str_out, "\tStake value: %s\n", dap_chain_balance_print(l_stake_value));
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNING_ADDR:
                if (l_tsd->size > sizeof(dap_chain_addr_t)) {
                    dap_string_append_printf(a_str_out, "\tSigning addr: <WRONG SIZE>\n");
                    break;
                }
                dap_chain_addr_t *l_stake_addr_signing = /*{ };
                _dap_tsd_get_scalar(l_tsd, &l_stake_addr_signing);*/ _dap_tsd_get_object(l_tsd, dap_chain_addr_t);
                dap_string_append_printf(a_str_out, "\tSigning addr: %s\n", dap_chain_addr_to_str(l_stake_addr_signing));
                dap_chain_hash_fast_t l_pkey_signing = l_stake_addr_signing->data.hash_fast;
                char l_pkey_signing_str[DAP_HASH_FAST_STR_SIZE];
                dap_strcmp(a_hash_out_type, "hex")
                        ? (int)dap_enc_base58_encode(&l_pkey_signing, sizeof(l_pkey_signing), l_pkey_signing_str)
                        : dap_chain_hash_fast_to_str(&l_pkey_signing, l_pkey_signing_str, sizeof(l_pkey_signing_str));
                dap_string_append_printf(a_str_out, "\tSigning pkey fingerprint: %s\n", l_pkey_signing_str);
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNER_NODE_ADDR:
                if(l_tsd->size > sizeof(dap_chain_node_addr_t)){
                    dap_string_append_printf(a_str_out, "\tNode addr: <WRONG SIZE>\n");
                    break;
                }
                dap_chain_node_addr_t *l_node_addr = _dap_tsd_get_object(l_tsd, dap_chain_node_addr_t);
                dap_string_append_printf(a_str_out, "\tNode addr: "NODE_ADDR_FP_STR"\n",
                                         NODE_ADDR_FP_ARGS(l_node_addr));
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_VALUE:
                if (l_tsd->size > sizeof(uint256_t)) {
                    dap_string_append_printf(a_str_out, "\tMin value: <WRONG SIZE>\n");
                    break;
                }
                uint256_t l_min_value = uint256_0;
                _dap_tsd_get_scalar(l_tsd, &l_min_value);
                dap_string_append_printf(a_str_out, "\tMin value: %s\n", dap_chain_balance_print(l_min_value));
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_SIGNERS_COUNT:
                if (l_tsd->size > sizeof(uint256_t)) {
                    dap_string_append_printf(a_str_out, "\tMin signers count: <WRONG SIZE>\n");
                    break;
                }
                uint256_t l_min_signers_count = uint256_0;
                _dap_tsd_get_scalar(l_tsd, &l_min_signers_count);
                dap_string_append_printf(a_str_out, "\tMin signers count: %s\n", dap_chain_balance_print(l_min_signers_count));
                break;
            default:
                dap_string_append_printf(a_str_out, "\t<UNKNOWN_TYPE_TSD_SECTION>\n");
                break;
        }
    }
    dap_chain_datum_decree_certs_dump(a_str_out, a_decree->data_n_signs + a_decree->header.data_size,
                                      a_decree->header.signs_size, a_hash_out_type);
}

void dap_chain_datum_decree_certs_dump(dap_string_t * a_str_out, byte_t * a_signs, size_t a_certs_size, const char *a_hash_out_type)
{
    dap_string_append_printf(a_str_out, "signatures: ");
    if (!a_certs_size) {
        dap_string_append_printf(a_str_out, "<NONE>\n");
        return;
    }

    dap_string_append_printf(a_str_out, "\n");

    size_t l_offset = 0;
    for (int i = 1; l_offset < (a_certs_size); i++) {
        dap_sign_t *l_sign = (dap_sign_t *) (a_signs + l_offset);
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
        char l_hash_str[DAP_HASH_FAST_STR_SIZE];
        dap_strcmp(a_hash_out_type, "hex")
                ? (int)dap_enc_base58_encode(&l_pkey_hash, sizeof(l_pkey_hash), l_hash_str)
                : dap_chain_hash_fast_to_str(&l_pkey_hash, l_hash_str, sizeof(l_hash_str));
        dap_string_append_printf(a_str_out, "%d) %s, %s, %u bytes\n", i, l_hash_str,
                                 dap_sign_type_to_str(l_sign->header.type), l_sign->header.sign_size);
    }
}

dap_chain_datum_decree_t* dap_chain_datum_decree_sign_in_cycle(dap_cert_t ** a_certs, dap_chain_datum_decree_t *a_datum_decree,
                                                  size_t a_certs_count, size_t *a_total_sign_count)
{
    size_t l_cur_sign_offset = a_datum_decree->header.data_size + a_datum_decree->header.signs_size;
    size_t l_total_signs_size = a_datum_decree->header.signs_size, l_total_sign_count = 0;

    for(size_t i = 0; i < a_certs_count; i++)
    {
        dap_sign_t * l_sign = dap_cert_sign(a_certs[i],  a_datum_decree,
                                            sizeof(dap_chain_datum_decree_t) + a_datum_decree->header.data_size, 0);

        if (l_sign) {
            size_t l_sign_size = dap_sign_get_size(l_sign);
            a_datum_decree = DAP_REALLOC(a_datum_decree, sizeof(dap_chain_datum_decree_t) + l_cur_sign_offset + l_sign_size);
            memcpy((byte_t*)a_datum_decree->data_n_signs + l_cur_sign_offset, l_sign, l_sign_size);
            l_total_signs_size += l_sign_size;
            l_cur_sign_offset += l_sign_size;
            a_datum_decree->header.signs_size = l_total_signs_size;
            DAP_DELETE(l_sign);
            log_it(L_DEBUG,"<-- Signed with '%s'", a_certs[i]->name);
            l_total_sign_count++;
        }
    }

    *a_total_sign_count = l_total_sign_count;
    return a_datum_decree;
}
