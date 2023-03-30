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
    if (!a_decree)
        return NULL;

    dap_sign_t *l_signs_section = (dap_sign_t *)(a_decree->data_n_signs + a_decree->header.data_size);

    *a_signs_size = a_decree->header.signs_size;

    return l_signs_section;
}

int dap_chain_datum_decree_get_fee(dap_chain_datum_decree_t *a_decree, uint256_t *a_fee_value)
{
    if(!a_decree || !a_fee_value){
        log_it(L_WARNING,"Wrong arguments");
        return -1;
    }

    size_t l_tsd_offset = 0, tsd_data_size = a_decree->header.data_size;

    while(l_tsd_offset < tsd_data_size){
        dap_tsd_t *l_tsd = (dap_tsd_t *)(a_decree->data_n_signs + l_tsd_offset);
        size_t l_tsd_size = l_tsd->size + sizeof(dap_tsd_t);
        if(l_tsd_size > tsd_data_size){
            log_it(L_WARNING,"TSD size is greater than all data size. It's possible corrupt data.");
            return -1;
        }
        if (l_tsd->type == DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE){
            if(l_tsd->size > sizeof(uint256_t)){
                log_it(L_WARNING,"Wrong fee tsd data size.");
                return -1;
            }
            *a_fee_value = dap_tsd_get_scalar(l_tsd, uint256_t);
            return 0;
        }
        l_tsd_offset += l_tsd_size;
    }
    return 1;
}

int dap_chain_datum_decree_get_fee_addr(dap_chain_datum_decree_t *a_decree, dap_chain_addr_t *a_fee_wallet)
{
    if(!a_decree || !a_fee_wallet){
        log_it(L_WARNING,"Wrong arguments");
        return -1;
    }

    size_t l_tsd_offset = 0, tsd_data_size = a_decree->header.data_size;

    while(l_tsd_offset < tsd_data_size){
        dap_tsd_t *l_tsd = (dap_tsd_t *)(a_decree->data_n_signs + l_tsd_offset);
        size_t l_tsd_size = l_tsd->size + sizeof(dap_tsd_t);
        if(l_tsd_size > tsd_data_size){
            log_it(L_WARNING,"TSD size is greater than all data size. It's possible corrupt data.");
            return -1;
        }
        if (l_tsd->type == DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE_WALLET){
            if(l_tsd->size > sizeof(dap_chain_addr_t)){
                log_it(L_WARNING,"Wrong fee tsd data size.");
                return -1;
            }
            dap_chain_addr_t l_addr = {0};
            l_addr = dap_tsd_get_scalar(l_tsd, dap_chain_addr_t);
            *a_fee_wallet = l_addr;
            return 0;
        }
        l_tsd_offset += l_tsd_size;
    }
    return 1;
}

dap_list_t *dap_chain_datum_decree_get_owners(dap_chain_datum_decree_t *a_decree, uint16_t *a_owners_num)
{
    if(!a_decree || !a_owners_num){
        log_it(L_WARNING,"Wrong arguments");
        return NULL;
    }

    size_t l_tsd_offset = 0, tsd_data_size = a_decree->header.data_size;
    uint64_t l_owners_num = 0;
    dap_list_t *l_key_list = NULL;


    while(l_tsd_offset < tsd_data_size){
        dap_tsd_t *l_tsd = (dap_tsd_t *)(a_decree->data_n_signs + l_tsd_offset);
        size_t l_tsd_size = dap_tsd_size(l_tsd);
        if(l_tsd_size > tsd_data_size){
            log_it(L_WARNING,"TSD size is greater than all data size. It's possible corrupt data.");
            if (l_key_list)
                dap_list_free_full(l_key_list, NULL);
            return NULL;
        }
        if (l_tsd->type == DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER){
            dap_pkey_t *l_owner_pkey = DAP_NEW_Z_SIZE(dap_pkey_t, l_tsd->size);
            if (!l_owner_pkey){
                log_it(L_WARNING,"Memory allocate failed.");
                dap_list_free_full(l_key_list, NULL);
                return NULL;
            }

            memcpy(l_owner_pkey, l_tsd->data, l_tsd->size);
            l_key_list = dap_list_append(l_key_list, l_owner_pkey);
            l_owners_num++;
        }
        l_tsd_offset += l_tsd_size;
    }
    if (a_owners_num)
        *a_owners_num = l_owners_num;
    return l_key_list;
}

int dap_chain_datum_decree_get_min_owners(dap_chain_datum_decree_t *a_decree, uint16_t *a_min_owners_num)
{
    if(!a_decree || !a_min_owners_num){
        log_it(L_WARNING,"Wrong arguments");
        return -1;
    }

    size_t l_tsd_offset = 0, tsd_data_size = a_decree->header.data_size;

    while(l_tsd_offset < tsd_data_size){
        dap_tsd_t *l_tsd = (dap_tsd_t *)(a_decree->data_n_signs + l_tsd_offset);
        size_t l_tsd_size = dap_tsd_size(l_tsd);
        if(l_tsd_size > tsd_data_size){
            log_it(L_WARNING,"TSD size is greater than all data size. It's possible corrupt data.");
            return -1;
        }
        if (l_tsd->type == DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER){
            if(l_tsd->size > sizeof(uint256_t)){
                log_it(L_WARNING,"Wrong fee tsd data size.");
                return -1;
            }
            uint256_t l_min_owners_num = dap_tsd_get_scalar(l_tsd, uint256_t);
            if (a_min_owners_num)
                *a_min_owners_num = dap_chain_uint256_to(l_min_owners_num);
            return 0;
        }
        l_tsd_offset += l_tsd_size;
    }
    return 1;
}

int dap_chain_datum_decree_get_stake_tx_hash(dap_chain_datum_decree_t *a_decree, dap_hash_fast_t *a_tx_hash)
{
    if(!a_decree || !a_tx_hash){
        log_it(L_WARNING,"Wrong arguments");
        return -1;
    }

    size_t l_tsd_offset = 0, tsd_data_size = a_decree->header.data_size;

    while(l_tsd_offset < tsd_data_size){
        dap_tsd_t *l_tsd = (dap_tsd_t *)(a_decree->data_n_signs + l_tsd_offset);
        size_t l_tsd_size = dap_tsd_size(l_tsd);
        if(l_tsd_size > tsd_data_size){
            log_it(L_WARNING,"TSD size is greater than all data size. It's possible corrupt data.");
            return -1;
        }
        if (l_tsd->type == DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_TX_HASH){
            if(l_tsd->size > sizeof(dap_hash_fast_t)){
                log_it(L_WARNING,"Wrong fee tsd data size.");
                return -1;
            }
            *a_tx_hash = dap_tsd_get_scalar(l_tsd, dap_hash_fast_t);
            return 0;
        }
        l_tsd_offset += l_tsd_size;
    }
    return 1;
}

int dap_chain_datum_decree_get_stake_value(dap_chain_datum_decree_t *a_decree, uint256_t *a_stake_value)
{
    if(!a_decree || !a_stake_value){
        log_it(L_WARNING,"Wrong arguments");
        return -1;
    }

    size_t l_tsd_offset = 0, tsd_data_size = a_decree->header.data_size;

    while(l_tsd_offset < tsd_data_size){
        dap_tsd_t *l_tsd = (dap_tsd_t *)(a_decree->data_n_signs + l_tsd_offset);
        size_t l_tsd_size = dap_tsd_size(l_tsd);
        if(l_tsd_size > tsd_data_size){
            log_it(L_WARNING,"TSD size is greater than all data size. It's possible corrupt data.");
            return -1;
        }
        if (l_tsd->type == DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_VALUE){
            if(l_tsd->size > sizeof(uint256_t)){
                log_it(L_WARNING,"Wrong fee tsd data size.");
                return -1;
            }
            *a_stake_value = dap_tsd_get_scalar(l_tsd, uint256_t);
            return 0;
        }
        l_tsd_offset += l_tsd_size;
    }
    return 1;
}

int dap_chain_datum_decree_get_stake_signing_addr(dap_chain_datum_decree_t *a_decree, dap_chain_addr_t *a_signing_addr)
{
    if(!a_decree || !a_signing_addr){
        log_it(L_WARNING,"Wrong arguments");
        return -1;
    }

    size_t l_tsd_offset = 0, tsd_data_size = a_decree->header.data_size;

    while(l_tsd_offset < tsd_data_size){
        dap_tsd_t *l_tsd = (dap_tsd_t *)(a_decree->data_n_signs + l_tsd_offset);
        size_t l_tsd_size = dap_tsd_size(l_tsd);
        if(l_tsd_size > tsd_data_size){
            log_it(L_WARNING,"TSD size is greater than all data size. It's possible corrupt data.");
            return -1;
        }
        if (l_tsd->type == DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNING_ADDR){
            if(l_tsd->size > sizeof(dap_chain_addr_t)){
                log_it(L_WARNING,"Wrong fee tsd data size.");
                return -1;
            }
            *a_signing_addr = dap_tsd_get_scalar(l_tsd, dap_chain_addr_t);
            return 0;
        }
        l_tsd_offset += l_tsd_size;
    }
    return 1;
}

int dap_chain_datum_decree_get_stake_signer_node_addr(dap_chain_datum_decree_t *a_decree, dap_chain_node_addr_t *a_node_addr)
{
    if(!a_decree || !a_node_addr){
        log_it(L_WARNING,"Wrong arguments");
        return -1;
    }

    size_t l_tsd_offset = 0, tsd_data_size = a_decree->header.data_size;

    while(l_tsd_offset < tsd_data_size){
        dap_tsd_t *l_tsd = (dap_tsd_t *)(a_decree->data_n_signs + l_tsd_offset);
        size_t l_tsd_size = dap_tsd_size(l_tsd);
        if(l_tsd_size > tsd_data_size){
            log_it(L_WARNING,"TSD size is greater than all data size. It's possible corrupt data.");
            return -1;
        }
        if (l_tsd->type == DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNER_NODE_ADDR){
            if(l_tsd->size > sizeof(dap_chain_node_addr_t)){
                log_it(L_WARNING,"Wrong fee tsd data size.");
                return -1;
            }
            *a_node_addr = dap_tsd_get_scalar(l_tsd, dap_chain_node_addr_t);
            return 0;
        }
        l_tsd_offset += l_tsd_size;
    }
    return 1;
}

int dap_chain_datum_decree_get_stake_min_value(dap_chain_datum_decree_t *a_decree, uint256_t *a_min_value)
{
    if(!a_decree || !a_min_value){
        log_it(L_WARNING,"Wrong arguments");
        return -1;
    }

    size_t l_tsd_offset = 0, tsd_data_size = a_decree->header.data_size;

    while(l_tsd_offset < tsd_data_size){
        dap_tsd_t *l_tsd = (dap_tsd_t *)(a_decree->data_n_signs + l_tsd_offset);
        size_t l_tsd_size = dap_tsd_size(l_tsd);
        if(l_tsd_size > tsd_data_size){
            log_it(L_WARNING,"TSD size is greater than all data size. It's possible corrupt data.");
            return -1;
        }
        if (l_tsd->type == DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_VALUE){
            if(l_tsd->size > sizeof(uint256_t)){
                log_it(L_WARNING,"Wrong fee tsd data size.");
                return -1;
            }
            *a_min_value = dap_tsd_get_scalar(l_tsd, uint256_t);
            return 0;
        }
        l_tsd_offset += l_tsd_size;
    }
    return 1;
}

int dap_chain_datum_decree_get_stake_min_signers_count(dap_chain_datum_decree_t *a_decree, uint256_t *a_min_signers_count)
{
    if(!a_decree || !a_min_signers_count){
        log_it(L_WARNING,"Wrong arguments");
        return -1;
    }

    size_t l_tsd_offset = 0, tsd_data_size = a_decree->header.data_size;

    while(l_tsd_offset < tsd_data_size){
        dap_tsd_t *l_tsd = (dap_tsd_t *)(a_decree->data_n_signs + l_tsd_offset);
        size_t l_tsd_size = dap_tsd_size(l_tsd);
        if(l_tsd_size > tsd_data_size){
            log_it(L_WARNING,"TSD size is greater than all data size. It's possible corrupt data.");
            return -1;
        }
        if (l_tsd->type == DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_SIGNERS_COUNT){
            if(l_tsd->size > sizeof(uint256_t)){
                log_it(L_WARNING,"Wrong fee tsd data size.");
                return -1;
            }
            *a_min_signers_count = dap_tsd_get_scalar(l_tsd, uint256_t);
            return 0;
        }
        l_tsd_offset += l_tsd_size;
    }
    return 1;
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
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGN:
//                return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGN";
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE:
                if (l_tsd->size > sizeof(uint256_t)){
                    dap_string_append_printf(a_str_out, "\tFee: <WRONG SIZE>\n");
                    break;
                }
                uint256_t l_fee_value = dap_tsd_get_scalar(l_tsd, uint256_t);
                char *l_fee_value_str = dap_chain_balance_print(l_fee_value);
                dap_string_append_printf(a_str_out, "\tFee: %s\n", l_fee_value_str);
                DAP_DELETE(l_fee_value_str);
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER:
                if (l_tsd->size < sizeof(dap_pkey_t)) {
                    dap_string_append_printf(a_str_out, "\tOwner fingerprint: <WRONG SIZE>\n");
                    break;
                }
                dap_pkey_t *l_owner_pkey = DAP_NEW_Z_SIZE(dap_pkey_t, l_tsd->size);
                memcpy(l_owner_pkey, l_tsd->data, l_tsd->size);
                dap_hash_fast_t l_owner_pkey_hash = {0};
                dap_hash_fast(l_owner_pkey->pkey, l_owner_pkey->header.size, &l_owner_pkey_hash);
                char *l_owner_pkey_str = dap_chain_hash_fast_to_str_new(&l_owner_pkey_hash);
                dap_string_append_printf(a_str_out, "\tOwner fingerprint: %s\n", l_owner_pkey_str);
                DAP_DELETE(l_owner_pkey_str);
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER:
                if (l_tsd->size > sizeof(uint256_t)){
                    dap_string_append_printf(a_str_out, "\tOwner min: <WRONG SIZE>\n");
                    break;
                }
                uint256_t l_owner_min = dap_tsd_get_scalar(l_tsd, uint256_t);
                char *l_owner_min_str = dap_chain_balance_print(l_owner_min);
                dap_string_append_printf(a_str_out, "\tOwner min: %s\n", l_owner_min_str);
                DAP_DELETE(l_owner_min_str);
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE_WALLET:
                if (l_tsd->size > sizeof(dap_chain_addr_t)) {
                    dap_string_append_printf(a_str_out, "\tWallet for fee: <WRONG SIZE>\n");
                    break;
                }
                dap_chain_addr_t l_addr_fee_wallet = {0};
                l_addr_fee_wallet = dap_tsd_get_scalar(l_tsd, dap_chain_addr_t);
                char *l_addr_fee_wallet_str = dap_chain_addr_to_str(&l_addr_fee_wallet);
                dap_string_append_printf(a_str_out, "\tWallet for fee: %s\n", l_addr_fee_wallet_str);
                DAP_DELETE(l_addr_fee_wallet_str);
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_TX_HASH:
                if (l_tsd->size > sizeof(dap_hash_fast_t)) {
                    dap_string_append_printf(a_str_out, "\tStake tx: <WRONG SIZE>\n");
                    break;
                }
                dap_hash_fast_t l_stake_tx = {0};
                l_stake_tx = dap_tsd_get_scalar(l_tsd, dap_hash_fast_t);
                char *l_stake_tx_hash = "";
                if (strcmp(a_hash_out_type, "hex") == 0) {
                    l_stake_tx_hash = dap_hash_fast_to_str_new(&l_stake_tx);
                } else {
                    l_stake_tx_hash = dap_enc_base58_encode_hash_to_str(&l_stake_tx);
                }
                dap_string_append_printf(a_str_out, "\tStake tx: %s\n", l_stake_tx_hash);
                DAP_DELETE(l_stake_tx_hash);
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_VALUE:
                if (l_tsd->size > sizeof(uint256_t)){
                    dap_string_append_printf(a_str_out, "\tStake value: <WRONG SIZE>\n");
                    break;
                }
                uint256_t l_stake_value = dap_tsd_get_scalar(l_tsd, uint256_t);
                char *l_stake_value_str = dap_chain_balance_print(l_stake_value);
                dap_string_append_printf(a_str_out, "\tStake value:%s\n", l_stake_value_str);
                DAP_DELETE(l_stake_value_str);
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNING_ADDR:
                if (l_tsd->size > sizeof(dap_chain_addr_t)) {
                    dap_string_append_printf(a_str_out, "\tSigning addr: <WRONG SIZE>\n");
                    break;
                }
                dap_chain_addr_t l_stake_addr_signing = {0};
                l_stake_addr_signing = dap_tsd_get_scalar(l_tsd, dap_chain_addr_t);
                char *l_stake_addr_signing_str = dap_chain_addr_to_str(&l_stake_addr_signing);
                dap_string_append_printf(a_str_out, "\tSigning addr: %s\n", l_stake_addr_signing_str);
                dap_chain_hash_fast_t *l_pkey_signing = DAP_NEW(dap_chain_hash_fast_t);
                memcpy(l_pkey_signing, l_stake_addr_signing.data.key, sizeof(dap_chain_hash_fast_t));
                char *l_pkey_signing_str = NULL;
                if (strcmp(a_hash_out_type, "hex") == 0) {
                    l_pkey_signing_str = dap_hash_fast_to_str_new(l_pkey_signing);
                } else {
                    l_pkey_signing_str = dap_enc_base58_encode_hash_to_str(l_pkey_signing);
                }
                dap_string_append_printf(a_str_out, "\tSigning pkey fingerprint: %s\n", l_stake_addr_signing_str);
                DAP_DELETE(l_stake_addr_signing_str);
                DAP_DELETE(l_pkey_signing_str);
                DAP_DELETE(l_pkey_signing);
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNER_NODE_ADDR:
                if(l_tsd->size > sizeof(dap_chain_node_addr_t)){
                    dap_string_append_printf(a_str_out, "\tNode addr: <WRONG SIZE>\n");
                    break;
                }
                dap_chain_node_addr_t l_node_addr = dap_tsd_get_scalar(l_tsd, dap_chain_node_addr_t);
                dap_string_append_printf(a_str_out, "\tNode addr: "NODE_ADDR_FP_STR"\n",
                                         NODE_ADDR_FP_ARGS_S(l_node_addr));
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_VALUE:
                if (l_tsd->size > sizeof(uint256_t)) {
                    dap_string_append_printf(a_str_out, "\tMin value: <WRONG SIZE>\n");
                    break;
                }
                uint256_t l_min_value = dap_tsd_get_scalar(l_tsd, uint256_t);
                char *l_min_value_str = dap_chain_balance_print(l_min_value);
                dap_string_append_printf(a_str_out, "\tMin value: %s\n", l_min_value_str);
                DAP_DELETE(l_min_value_str);
                break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_SIGNERS_COUNT:
                if (l_tsd->size > sizeof(uint256_t)) {
                    dap_string_append_printf(a_str_out, "\tMin signers count: <WRONG SIZE>\n");
                    break;
                }
                uint256_t l_min_signers_count = dap_tsd_get_scalar(l_tsd, uint256_t);
                char *l_min_signers_count_str = dap_chain_balance_print(l_min_signers_count);
                dap_string_append_printf(a_str_out, "\tMin signers count: %s\n", l_min_signers_count_str);
                DAP_DELETE(l_min_signers_count_str);
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

        char *l_hash_str = NULL;
        if(!dap_strcmp(a_hash_out_type, "hex"))
            l_hash_str = dap_chain_hash_fast_to_str_new(&l_pkey_hash);
        else
            l_hash_str = dap_enc_base58_encode_hash_to_str(&l_pkey_hash);

        dap_string_append_printf(a_str_out, "%d) %s, %s, %u bytes\n", i, l_hash_str,
                                 dap_sign_type_to_str(l_sign->header.type), l_sign->header.sign_size);
        DAP_DEL_Z(l_hash_str);
    }
}
