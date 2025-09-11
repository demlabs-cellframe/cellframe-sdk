/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
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
#include <string.h>
#include "dap_json.h"

#include "dap_common.h"
#include "dap_time.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_datum_anchor.h"
#include "dap_chain_datum_tx_voting.h"
#include "dap_chain_datum_tx_receipt.h"
#include "dap_chain_datum_tx_pkey.h"
#include "dap_chain_datum_hashtree_roots.h"
#include "dap_enc_base58.h"
#include "dap_sign.h"
#include "dap_tsd.h"
#include "dap_json_rpc_errors.h"
#include "dap_chain_net.h"
#include "dap_chain_ledger.h"

#define LOG_TAG "dap_chain_datum"

/**
 * @brief dap_chain_datum_create
 * @param a_type_id
 * @param a_data
 * @param a_data_size
 * @return
 */
dap_chain_datum_t *dap_chain_datum_create(uint16_t a_type_id, const void *a_data, size_t a_data_size)
{
   dap_chain_datum_t *l_datum = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_datum_t, sizeof(dap_chain_datum_t) + a_data_size, NULL);
   *l_datum = (dap_chain_datum_t) {
        .header = {
            .version_id = DAP_CHAIN_DATUM_VERSION,
            .type_id    = a_type_id,
            .data_size  = (uint32_t)a_data_size,
            .ts_create  = dap_time_now()
        }
    };
    if (a_data && a_data_size)
        memcpy(l_datum->data, a_data, (uint32_t)a_data_size);
    return  l_datum;
}
void dap_datum_token_dump_tsd_to_json(dap_json_t * json_obj_out, dap_chain_datum_token_t *a_token, size_t a_token_size, const char *a_hash_out_type)
{
    dap_tsd_t *l_tsd_begin = dap_chain_datum_token_tsd_get(a_token, a_token_size);
    if (!l_tsd_begin) {
        dap_json_object_add_string(json_obj_out, "status", "<CORRUPTED TSD SECTION>");
        return;
    }
    size_t l_tsd_total_size = 0;
    switch (a_token->type) {
    case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL:
        switch (a_token->subtype) {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
            l_tsd_total_size = a_token->header_private_decl.tsd_total_size; break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
            l_tsd_total_size = a_token->header_native_decl.tsd_total_size; break;
        default: break;
        } break;
    case DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE:
        switch (a_token->subtype) {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
            l_tsd_total_size = a_token->header_private_update.tsd_total_size; break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
            l_tsd_total_size = a_token->header_native_update.tsd_total_size; break;
        default: break;
        } break;
    default: break;
    }
    dap_tsd_t *l_tsd; size_t l_tsd_size;
    dap_tsd_iter(l_tsd, l_tsd_size, l_tsd_begin, l_tsd_total_size) {
        switch(l_tsd->type) {
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_SET_FLAGS: {
            uint16_t l_t = 0;
            dap_chain_datum_token_flags_dump_to_json(json_obj_out, "flags_set", _dap_tsd_get_scalar(l_tsd, &l_t));
            continue;
        }
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS: {
            uint16_t l_t = 0;
            dap_chain_datum_token_flags_dump_to_json(json_obj_out, "flags_unset", _dap_tsd_get_scalar(l_tsd, &l_t));
            continue;
        }
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY: {     // 256
            uint256_t l_t = uint256_0;
            char *l_balance = dap_chain_balance_datoshi_print(_dap_tsd_get_scalar(l_tsd, &l_t));
            dap_json_object_add(json_obj_out, "total_supply", dap_dap_json_object_new_string(l_balance));
            DAP_DELETE(l_balance);
            continue;
        }
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID: {
            uint16_t l_t = 0;
            dap_json_object_add_int(json_obj_out, "total_signs_valid", _dap_tsd_get_scalar(l_tsd, &l_t));
            continue;
        }
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_ADD:
            if(l_tsd->size >= sizeof(dap_pkey_t)) {
                    char *l_hash_str;
                    dap_pkey_t *l_pkey = (dap_pkey_t*)l_tsd->data;
                    dap_hash_fast_t l_hf = { };
                    if (!dap_pkey_get_hash(l_pkey, &l_hf)) {
                        dap_json_object_add(json_obj_out, "total_pkeys_add", dap_dap_json_object_new_string("<WRONG CALCULATION FINGERPRINT>"));
                    } else {
                        if (!dap_strcmp(a_hash_out_type, "hex") || !dap_strcmp(a_hash_out_type, "content_hash"))
                            l_hash_str = dap_chain_hash_fast_to_str_new(&l_hf);
                        else
                            l_hash_str = dap_enc_base58_encode_hash_to_str(&l_hf);
                        dap_json_object_add(json_obj_out, "total_pkeys_add", dap_dap_json_object_new_string(l_hash_str));
                        DAP_DELETE(l_hash_str);
                    }
            } else
                    dap_json_object_add_int(json_obj_out, "total_pkeys_add_with_wrong_size", l_tsd->size);
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_REMOVE:
            if(l_tsd->size == sizeof(dap_chain_hash_fast_t) ){
                    char *l_hash_str = (!dap_strcmp(a_hash_out_type,"hex")|| !dap_strcmp(a_hash_out_type, "content_hash"))
                                           ? dap_chain_hash_fast_to_str_new((dap_chain_hash_fast_t*) l_tsd->data)
                                           : dap_enc_base58_encode_hash_to_str((dap_chain_hash_fast_t*) l_tsd->data);
                    dap_json_object_add(json_obj_out, "total_pkeys_remove", dap_dap_json_object_new_string(l_hash_str));
                    DAP_DELETE( l_hash_str );
            } else
                    dap_json_object_add_int(json_obj_out, "total_pkeys_remove_with_wrong_size", l_tsd->size);
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK: {
            dap_chain_datum_token_tsd_delegate_from_stake_lock_t *l_tsd_section = _dap_tsd_get_object(l_tsd, dap_chain_datum_token_tsd_delegate_from_stake_lock_t);
            char *balance = dap_chain_balance_coins_print(l_tsd_section->emission_rate);
            dap_json_object_add(json_obj_out, "ticker_token_from", dap_dap_json_object_new_string((char*)l_tsd_section->ticker_token_from));
            dap_json_object_add(json_obj_out, "emission_rate", dap_dap_json_object_new_string(balance));
            DAP_DEL_Z(balance);
        }continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD  :
                dap_json_object_add(json_obj_out, "datum_type_allowed_add", dap_dap_json_object_new_string(dap_tsd_get_string_const(l_tsd)));
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_REMOVE  :
            dap_json_object_add(json_obj_out, "datum_type_allowed_remove", dap_dap_json_object_new_string(dap_tsd_get_string_const(l_tsd)));
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_ADD  :
            dap_json_object_add(json_obj_out, "datum_type_blocked_add", dap_dap_json_object_new_string(dap_tsd_get_string_const(l_tsd)));
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_REMOVE:
            dap_json_object_add(json_obj_out, "datum_type_blocked_remove", dap_dap_json_object_new_string(dap_tsd_get_string_const(l_tsd)));
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD: {
                dap_chain_addr_t *l_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
                dap_json_object_add(json_obj_out, "tx_sender_allowed_add", dap_dap_json_object_new_string(dap_chain_addr_to_str_static(l_addr)));
            } continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_REMOVE:{
                dap_chain_addr_t *l_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
                dap_json_object_add(json_obj_out, "tx_sender_allowed_remove", dap_dap_json_object_new_string(dap_chain_addr_to_str_static(l_addr)));
            } continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD: {
                dap_chain_addr_t *l_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
                dap_json_object_add(json_obj_out, "tx_sender_blocked_add", dap_dap_json_object_new_string(dap_chain_addr_to_str_static(l_addr)));
            } continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_REMOVE: {
                dap_chain_addr_t *l_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
                dap_json_object_add(json_obj_out, "tx_sender_blocked_remove", dap_dap_json_object_new_string(dap_chain_addr_to_str_static(l_addr)));
            } continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD: {
                dap_chain_addr_t *l_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
                dap_json_object_add(json_obj_out, "tx_receiver_allowed_add", dap_dap_json_object_new_string(dap_chain_addr_to_str_static(l_addr)));
            } continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_REMOVE: {
                dap_chain_addr_t *l_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
                dap_json_object_add(json_obj_out, "tx_receiver_allowed", dap_dap_json_object_new_string(dap_chain_addr_to_str_static(l_addr)));
            } continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD: {
                dap_chain_addr_t *l_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
                dap_json_object_add(json_obj_out, "tx_receiver_blocked_add", dap_dap_json_object_new_string(dap_chain_addr_to_str_static(l_addr)));
            } continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_REMOVE: {
                dap_chain_addr_t *l_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
                dap_json_object_add(json_obj_out, "tx_receiver_blocked_remove", dap_dap_json_object_new_string(dap_chain_addr_to_str_static(l_addr)));
            } continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TOKEN_DESCRIPTION:
            dap_json_object_add(json_obj_out, "description", dap_dap_json_object_new_string(dap_tsd_get_string_const(l_tsd)));
            continue;
        default: {
                char l_tsd_type_char[50] = {};
                snprintf(l_tsd_type_char, 50, "<0x%04hX>", l_tsd->type);
                dap_json_object_add(json_obj_out, "tsd_type", dap_dap_json_object_new_string(l_tsd_type_char));
                dap_json_object_add_int(json_obj_out, "tsd_size", l_tsd->size);
            }
        }
    }
}

/**
 * @brief _dap_chain_datum_tx_out_data
 *
 * @param a_datum
 * @param a_ledger
 * @param a_str_out
 * @param a_hash_out_type
 * @param save_processed_tx
 * @param a_tx_hash_processed
 * @param l_tx_num
 */
bool dap_chain_datum_dump_tx_json(dap_json_t* a_json_arr_reply,
                             dap_chain_datum_tx_t *a_datum,
                             const char *a_ticker,
                             dap_json_t* json_obj_out,
                             const char *a_hash_out_type,
                             dap_hash_fast_t *a_tx_hash,
                             dap_chain_net_id_t a_net_id,
                             int a_version)
{
    bool l_is_first = false;
    dap_chain_tx_in_t *l_in_item = (dap_chain_tx_in_t *)dap_chain_datum_tx_item_get(a_datum, NULL, NULL, TX_ITEM_TYPE_IN, NULL);
    if (l_in_item && dap_hash_fast_is_blank(&l_in_item->header.tx_prev_hash))
        l_is_first = true;
    char l_tmp_buf[DAP_TIME_STR_SIZE];
    const char *l_hash_str = dap_strcmp(a_hash_out_type, "hex")
            ? dap_enc_base58_encode_hash_to_str_static(a_tx_hash)
            : dap_chain_hash_fast_to_str_static(a_tx_hash);
    dap_json_t* json_arr_items = dap_json_array_new();
    dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, a_datum->header.ts_created);
    l_is_first ? 
    dap_json_object_add(json_obj_out, a_version == 1 ? "first transaction" : "first_transaction", dap_dap_json_object_new_string("emit")):
    dap_json_object_add(json_obj_out, a_version == 1 ?  "first transaction" : "first_transaction", dap_dap_json_object_new_string(a_version == 1 ? "" : "empty"));
    dap_json_object_add(json_obj_out, "hash", dap_dap_json_object_new_string(l_hash_str));
    dap_json_object_add(json_obj_out, a_version == 1 ?  "tx created" : "tx_created", dap_dap_json_object_new_string(l_tmp_buf));
    dap_json_object_add(json_obj_out, a_version == 1 ?  "token ticker" : "token_ticker", a_ticker ? dap_dap_json_object_new_string(a_ticker) : dap_dap_json_object_new_string(a_version == 1 ? "" : "empty"));
    //json_object_array_add(json_arr_items, json_obj_tx);

    dap_hash_fast_t l_hash_tmp = { };
    byte_t *item; size_t l_size;
    TX_ITEM_ITER_TX(item, l_size, a_datum) {
        dap_json_t* json_obj_item = dap_json_object_new();
        if (a_version != 1)
            dap_json_object_add(json_obj_item, "item_type", dap_dap_json_object_new_string(dap_chain_datum_tx_item_type_to_str_short(*item)));
        switch (*item) {
        case TX_ITEM_TYPE_IN:
            l_hash_tmp = ((dap_chain_tx_in_t*)item)->header.tx_prev_hash;
            l_hash_str = !dap_hash_fast_is_blank(&l_hash_tmp)
                ? dap_strcmp(a_hash_out_type, "hex") ? dap_enc_base58_encode_hash_to_str_static(&l_hash_tmp) : dap_chain_hash_fast_to_str_static(&l_hash_tmp)
                : "BLANK";
            if (a_version == 1)
                dap_json_object_add(json_obj_item, "item type", dap_dap_json_object_new_string("IN"));
            dap_json_object_add(json_obj_item, a_version == 1 ? "Tx prev hash" : "tx_prev_hash", dap_dap_json_object_new_string(l_hash_str));
            dap_json_object_add(json_obj_item, a_version == 1 ? "Tx out prev idx" : "tx_out_prev_idx", dap_json_object_new_uint64(((dap_chain_tx_in_t*)item)->header.tx_out_prev_idx));
            break;
        case TX_ITEM_TYPE_OUT_OLD: {
            const char *l_value_str = dap_uint256_to_char(
                dap_chain_uint256_from(((dap_chain_tx_out_old_t*)item)->header.value), NULL );
            if (a_version == 1)
                dap_json_object_add(json_obj_item, "item type", dap_dap_json_object_new_string("OUT OLD"));
            dap_json_object_add(json_obj_item, a_version == 1 ? "Value" : "value", dap_dap_json_object_new_string(l_value_str));
            dap_json_object_add(json_obj_item, a_version == 1 ? "Address" : "addr", dap_dap_json_object_new_string(dap_chain_addr_to_str_static(&((dap_chain_tx_out_old_t*)item)->addr)));
        } break;
        case TX_ITEM_TYPE_OUT: { // 256
            const char *l_coins_str,
                    *l_value_str = dap_uint256_to_char(((dap_chain_tx_out_t*)item)->header.value, &l_coins_str),
                    *l_addr_str = dap_chain_addr_to_str_static(&((dap_chain_tx_out_t*)item)->addr);
            if (a_version == 1)
                dap_json_object_add(json_obj_item, "item type", dap_dap_json_object_new_string("OUT"));
            dap_json_object_add(json_obj_item, a_version == 1 ? "Coins" : "coins", dap_dap_json_object_new_string(l_coins_str));
            dap_json_object_add(json_obj_item, a_version == 1 ? "Value": "value", dap_dap_json_object_new_string(l_value_str));
            dap_json_object_add(json_obj_item, a_version == 1 ? "Address" : "addr", dap_dap_json_object_new_string(l_addr_str));            
        } break;
        case TX_ITEM_TYPE_IN_EMS: {
            char l_tmp_buff[70];
            l_hash_tmp = ((dap_chain_tx_in_ems_t*)item)->header.token_emission_hash;
            l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str_static(&l_hash_tmp)
                    : dap_chain_hash_fast_to_str_static(&l_hash_tmp);
            if (a_version == 1)
                dap_json_object_add(json_obj_item, "item type", dap_dap_json_object_new_string("IN_EMS"));
            dap_json_object_add(json_obj_item,"ticker", dap_dap_json_object_new_string(((dap_chain_tx_in_ems_t*)item)->header.ticker));
            dap_json_object_add(json_obj_item,"token_emission_hash", dap_dap_json_object_new_string(l_hash_str));
            snprintf(l_tmp_buff, sizeof(l_tmp_buff), "0x%016"DAP_UINT64_FORMAT_x"",((dap_chain_tx_in_ems_t*)item)->header.token_emission_chain_id.uint64);
            dap_json_object_add(json_obj_item,"token_emission_chain_id", dap_dap_json_object_new_string(l_tmp_buff));
        } break;

        case TX_ITEM_TYPE_IN_REWARD: {
            l_hash_tmp = ((dap_chain_tx_in_reward_t *)item)->block_hash;
            l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str_static(&l_hash_tmp)
                    : dap_chain_hash_fast_to_str_static(&l_hash_tmp);
            if (a_version == 1)
                dap_json_object_add(json_obj_item, "item type", dap_dap_json_object_new_string("IN_REWARD"));
            dap_json_object_add(json_obj_item,"block_hash", dap_dap_json_object_new_string(l_hash_str));
        } break;

        case TX_ITEM_TYPE_SIG: {
            dap_sign_t *l_sign = dap_chain_datum_tx_item_sig_get_sign((dap_chain_tx_sig_t*)item);
            if (a_version == 1)
                dap_json_object_add(json_obj_item, "item type", dap_dap_json_object_new_string("SIG"));
            dap_sign_get_information_json(l_sign, json_obj_item, a_hash_out_type, a_version);
            dap_chain_addr_t l_sender_addr;
            dap_chain_addr_fill_from_sign(&l_sender_addr, l_sign, a_net_id);
            dap_json_object_add(json_obj_item, a_version == 1 ? "Sender addr" : "sender_addr", dap_dap_json_object_new_string(dap_chain_addr_to_str_static(&l_sender_addr)));            
        } break;
        case TX_ITEM_TYPE_RECEIPT_OLD:{
            dap_chain_datum_tx_receipt_old_t *l_receipt_old = (dap_chain_datum_tx_receipt_old_t*)item;
            const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_receipt_old->receipt_info.value_datoshi, &l_coins_str);
            dap_json_object_add(json_obj_item,"item type", dap_dap_json_object_new_string("RECEIPT"));
            dap_json_object_add(json_obj_item,"size", dap_json_object_new_uint64(l_receipt_old->size));
            dap_json_object_add(json_obj_item,"ext size", dap_json_object_new_uint64(l_receipt_old->exts_size));
            dap_json_object_add(json_obj_item,"INFO", dap_dap_json_object_new_string(""));
            dap_json_object_add(json_obj_item,"units", dap_json_object_new_uint64(l_receipt_old->receipt_info.units));
            dap_json_object_add(json_obj_item,"uid", dap_json_object_new_uint64(l_receipt_old->receipt_info.srv_uid.uint64));
            dap_json_object_add(json_obj_item,"units type", dap_dap_json_object_new_string(dap_chain_srv_unit_enum_to_str(l_receipt_old->receipt_info.units_type.enm)));
            dap_json_object_add(json_obj_item,"coins", dap_dap_json_object_new_string(l_coins_str));
            dap_json_object_add(json_obj_item,"value", dap_dap_json_object_new_string(l_value_str));

            dap_json_object_add(json_obj_item,"Exts",dap_dap_json_object_new_string(""));                         
            switch (l_receipt_old->exts_size) {
            case (sizeof(dap_sign_t) * 2): {
                dap_sign_t *l_client = (dap_sign_t*)(l_receipt_old->exts_n_signs  + sizeof(dap_sign_t));
                dap_json_object_add(json_obj_item,"Client", dap_dap_json_object_new_string(""));
                dap_sign_get_information_json(l_client, json_obj_item, a_hash_out_type, a_version);                
            }
            case (sizeof(dap_sign_t)): {
                dap_sign_t *l_provider = (dap_sign_t*)(l_receipt_old->exts_n_signs);
                dap_json_object_add(json_obj_item,"Provider", dap_dap_json_object_new_string(""));
                dap_sign_get_information_json(l_provider,json_obj_item, a_hash_out_type, a_version);
                break;
            }
            }
        } break;
        case TX_ITEM_TYPE_RECEIPT: {
            const char *l_coins_str, *l_value_str = dap_uint256_to_char(((dap_chain_datum_tx_receipt_t*)item)->receipt_info.value_datoshi, &l_coins_str);
            if (a_version == 1)
                dap_json_object_add(json_obj_item, "item type", dap_dap_json_object_new_string("RECEIPT"));
            dap_json_object_add(json_obj_item, "size", dap_json_object_new_uint64(((dap_chain_datum_tx_receipt_t*)item)->size));
            dap_json_object_add(json_obj_item, a_version == 1 ? "ext size" : "ext_size", dap_json_object_new_uint64(((dap_chain_datum_tx_receipt_t*)item)->exts_size));
            dap_json_object_add(json_obj_item, a_version == 1 ? "INFO" : "info", dap_dap_json_object_new_string(""));
            dap_json_object_add(json_obj_item,"units", dap_json_object_new_uint64(((dap_chain_datum_tx_receipt_t*)item)->receipt_info.units));
            dap_json_object_add(json_obj_item,"uid", dap_json_object_new_uint64(((dap_chain_datum_tx_receipt_t*)item)->receipt_info.srv_uid.uint64));
            dap_json_object_add(json_obj_item, a_version == 1 ? "units type" : "units_type", dap_dap_json_object_new_string(dap_chain_srv_unit_enum_to_str(((dap_chain_datum_tx_receipt_t*)item)->receipt_info.units_type.enm)));
            dap_json_object_add(json_obj_item, "coins", dap_dap_json_object_new_string(l_coins_str));
            dap_json_object_add(json_obj_item,"value", dap_dap_json_object_new_string(l_value_str));
            if (a_version == 1)
                dap_json_object_add(json_obj_item, "Exts",dap_dap_json_object_new_string(""));                         
            switch ( ((dap_chain_datum_tx_receipt_t*)item)->exts_size ) {
            case (sizeof(dap_sign_t) * 2): {
                dap_sign_t *l_client = (dap_sign_t*)( ((dap_chain_datum_tx_receipt_t*)item)->exts_n_signs + sizeof(dap_sign_t) );
                dap_json_object_add(json_obj_item, a_version == 1 ? "Client" : "sig_inf", dap_dap_json_object_new_string(a_version == 1 ? "" : "client"));
                dap_sign_get_information_json(l_client, json_obj_item, a_hash_out_type, a_version);                
            }
            case (sizeof(dap_sign_t)): {
                dap_sign_t *l_provider = (dap_sign_t*)( ((dap_chain_datum_tx_receipt_t*)item)->exts_n_signs );
                dap_json_object_add(json_obj_item, a_version == 1 ? "Provider" : "sig_inf", dap_dap_json_object_new_string(a_version == 1 ? "" : "provider"));
                dap_sign_get_information_json(l_provider,json_obj_item, a_hash_out_type, a_version);
                break;
            }
            }
        } break;
        case TX_ITEM_TYPE_PKEY: {
            dap_pkey_t *l_pkey = (dap_pkey_t*)((dap_chain_tx_pkey_t*)item)->pkey;
            dap_chain_hash_fast_t l_pkey_hash;
            dap_hash_fast(l_pkey->pkey, l_pkey->header.size, &l_pkey_hash);
            l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str_static(&l_pkey_hash)
                    : dap_chain_hash_fast_to_str_static(&l_pkey_hash);
            if (a_version == 1)
                dap_json_object_add(json_obj_item, "item type", dap_dap_json_object_new_string("PKey"));
            dap_json_object_add(json_obj_item, a_version == 1 ? "PKey" : "pkey", dap_dap_json_object_new_string(""));
            dap_json_object_add(json_obj_item, a_version == 1 ? "SIG type" : "sig_type", dap_dap_json_object_new_string(dap_sign_type_to_str(((dap_chain_tx_pkey_t*)item)->header.sig_type)));
            dap_json_object_add(json_obj_item, a_version == 1 ? "SIG size" : "sig_size", dap_json_object_new_uint64(((dap_chain_tx_pkey_t*)item)->header.sig_size));
            dap_json_object_add(json_obj_item, a_version == 1 ? "Sequence number" : "seq_num", dap_json_object_new_uint64(((dap_chain_tx_pkey_t*)item)->seq_no));
            dap_json_object_add(json_obj_item, a_version == 1 ? "Key" : "key", dap_dap_json_object_new_string(""));
            dap_json_object_add(json_obj_item, a_version == 1 ? "Type" : "type", dap_dap_json_object_new_string(dap_pkey_type_to_str(l_pkey->header.type)));
            dap_json_object_add(json_obj_item, a_version == 1 ? "Size" : "size", dap_json_object_new_uint64(l_pkey->header.size));
            dap_json_object_add(json_obj_item, a_version == 1 ? "Hash" : "hash", dap_dap_json_object_new_string(l_hash_str));

        } break;
        case TX_ITEM_TYPE_TSD: {
            if (a_version == 1)
                dap_json_object_add(json_obj_item, "item type", dap_dap_json_object_new_string("TSD data"));
            dap_json_object_add(json_obj_item, a_version == 1 ? "type" : "data_type", dap_json_object_new_uint64(((dap_chain_tx_tsd_t*)item)->header.type));
            dap_json_object_add(json_obj_item,"size", dap_json_object_new_uint64(((dap_chain_tx_tsd_t*)item)->header.size));            
        } break;
        case TX_ITEM_TYPE_IN_COND:
            if (a_version == 1)
                dap_json_object_add(json_obj_item, "item type", dap_dap_json_object_new_string("IN COND"));
            l_hash_tmp = ((dap_chain_tx_in_cond_t*)item)->header.tx_prev_hash;
            l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str_static(&l_hash_tmp)
                    : dap_chain_hash_fast_to_str_static(&l_hash_tmp);
            dap_json_object_add(json_obj_item, a_version == 1 ? "Receipt_idx" : "receipt_idx", dap_dap_json_object_new_int(((dap_chain_tx_in_cond_t*)item)->header.receipt_idx));
            dap_json_object_add(json_obj_item, a_version == 1 ? "Tx_prev_hash" : "tx_prev_hash", dap_dap_json_object_new_string(l_hash_str));
            dap_json_object_add(json_obj_item, a_version == 1 ? "Tx_out_prev_idx" : "tx_out_prev_idx", dap_json_object_new_uint64(((dap_chain_tx_in_cond_t*)item)->header.tx_out_prev_idx));
            break;
        case TX_ITEM_TYPE_OUT_COND: {
            char l_tmp_buff[70];
            if (a_version == 1)
                dap_json_object_add(json_obj_item, "item type", dap_dap_json_object_new_string("OUT COND"));
            const char *l_coins_str, *l_value_str = dap_uint256_to_char(((dap_chain_tx_out_cond_t*)item)->header.value, &l_coins_str);
            dap_time_t l_ts_exp = ((dap_chain_tx_out_cond_t*)item)->header.ts_expires;
            dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_ts_exp);
            dap_json_object_add(json_obj_item,"ts_expires", l_ts_exp ? dap_dap_json_object_new_string(l_tmp_buf) : dap_dap_json_object_new_string("never"));
            dap_json_object_add(json_obj_item,"coins", dap_dap_json_object_new_string(l_coins_str));
            dap_json_object_add(json_obj_item,"value", dap_dap_json_object_new_string(l_value_str));
            dap_json_object_add(json_obj_item,"subtype", dap_dap_json_object_new_string(dap_chain_tx_out_cond_subtype_to_str(((dap_chain_tx_out_cond_t*)item)->header.subtype)));
            snprintf(l_tmp_buff, sizeof(l_tmp_buff), "0x%016"DAP_UINT64_FORMAT_x"",((dap_chain_tx_out_cond_t*)item)->header.srv_uid.uint64);
            dap_json_object_add(json_obj_item,"uid", dap_dap_json_object_new_string(l_tmp_buff));
            dap_json_object_add(json_obj_item, "tsd_size", dap_json_object_new_uint64(((dap_chain_tx_out_cond_t *)item)->tsd_size));
            switch (((dap_chain_tx_out_cond_t*)item)->header.subtype) {
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY: {
                    const char *l_coins_str, *l_value_str =
                        dap_uint256_to_char( ((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.unit_price_max_datoshi, &l_coins_str );
                    l_hash_tmp = ((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.pkey_hash;
                    l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                            ? dap_enc_base58_encode_hash_to_str_static(&l_hash_tmp)
                            : dap_chain_hash_fast_to_str_static(&l_hash_tmp);
                    snprintf(l_tmp_buff, sizeof(l_tmp_buff), "0x%08x",((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.unit.uint32);
                    dap_json_object_add(json_obj_item, "unit", dap_dap_json_object_new_string(l_tmp_buff));
                    dap_json_object_add(json_obj_item, "pkey", dap_dap_json_object_new_string(l_hash_str));
                    dap_json_object_add(json_obj_item, a_version == 1 ? "max price(coins)" : "max_price_coins", dap_dap_json_object_new_string(l_coins_str));
                    dap_json_object_add(json_obj_item, a_version == 1 ? "max price(value)" : "max_price_value", dap_dap_json_object_new_string(l_value_str));

                } break;
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE: {
                    dap_chain_node_addr_t *l_signer_node_addr = &((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake_pos_delegate.signer_node_addr;
                    dap_chain_addr_t *l_signing_addr = &((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake_pos_delegate.signing_addr;
                    l_hash_tmp = l_signing_addr->data.hash_fast;
                    l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                            ? dap_enc_base58_encode_hash_to_str_static(&l_hash_tmp)
                            : dap_chain_hash_fast_to_str_static(&l_hash_tmp);
                    dap_json_object_add(json_obj_item, a_version == 1 ? "signing_addr" : "sig_addr", dap_dap_json_object_new_string(dap_chain_addr_to_str_static(l_signing_addr)));
                    dap_json_object_add(json_obj_item, a_version == 1 ? "with pkey hash" : "sig_pkey_hash", dap_dap_json_object_new_string(l_hash_str));                    
                    snprintf(l_tmp_buff, sizeof(l_tmp_buff), ""NODE_ADDR_FP_STR"",NODE_ADDR_FP_ARGS(l_signer_node_addr));
                    dap_json_object_add(json_obj_item, a_version == 1 ? "signer_node_addr" : "sig_node_addr", dap_dap_json_object_new_string(l_tmp_buff));
                    
                } break;
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE: {
                    const char *l_rate_str;
                    dap_uint256_to_char( (((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.rate), &l_rate_str );
                    snprintf(l_tmp_buff,sizeof(l_tmp_buff),"0x%016"DAP_UINT64_FORMAT_x"",((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.buy_net_id.uint64);
                    dap_json_object_add(json_obj_item, a_version == 1 ? "net id" : "net_id", dap_dap_json_object_new_string(l_tmp_buff));
                    dap_json_object_add(json_obj_item,"buy_token", dap_dap_json_object_new_string(((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.buy_token));
                    dap_json_object_add(json_obj_item,"rate", dap_dap_json_object_new_string(l_rate_str));
                } break;
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK: {
                    dap_time_t l_ts_unlock = ((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake_lock.time_unlock;
                    dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_ts_unlock);
                    dap_json_object_add(json_obj_item,"time_unlock", dap_dap_json_object_new_string(l_tmp_buf));
                } break;
                default: break;
            }
        } break;
        case TX_ITEM_TYPE_OUT_EXT: {
            const char *l_coins_str, *l_value_str = dap_uint256_to_char( ((dap_chain_tx_out_ext_t*)item)->header.value, &l_coins_str );
            if (a_version == 1)
                dap_json_object_add(json_obj_item, "item type", dap_dap_json_object_new_string("OUT EXT"));
            dap_json_object_add(json_obj_item,"addr", dap_dap_json_object_new_string(dap_chain_addr_to_str_static(&((dap_chain_tx_out_ext_t*)item)->addr)));
            dap_json_object_add(json_obj_item,"token", dap_dap_json_object_new_string(((dap_chain_tx_out_ext_t*)item)->token));
            dap_json_object_add(json_obj_item,"coins", dap_dap_json_object_new_string(l_coins_str));
            dap_json_object_add(json_obj_item,"value", dap_dap_json_object_new_string(l_value_str));
        } break;

        case TX_ITEM_TYPE_OUT_STD: {
            const char *l_coins_str, *l_value_str = dap_uint256_to_char( ((dap_chain_tx_out_std_t *)item)->value, &l_coins_str );
            if (a_version == 1)
                dap_json_object_add(json_obj_item, "item type", dap_dap_json_object_new_string("OUT STD"));
            dap_json_object_add(json_obj_item, "addr", dap_dap_json_object_new_string(dap_chain_addr_to_str_static(&((dap_chain_tx_out_std_t *)item)->addr)));
            dap_json_object_add(json_obj_item, "token", dap_dap_json_object_new_string(((dap_chain_tx_out_std_t *)item)->token));
            dap_json_object_add(json_obj_item, "coins", dap_dap_json_object_new_string(l_coins_str));
            dap_json_object_add(json_obj_item, "value", dap_dap_json_object_new_string(l_value_str));
            dap_time_t l_ts_unlock = ((dap_chain_tx_out_std_t *)item)->ts_unlock;
            dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_ts_unlock);
            dap_json_object_add(json_obj_item, "time_unlock", dap_dap_json_object_new_string(l_ts_unlock ? l_tmp_buf : "not_locked"));
        } break;

        case TX_ITEM_TYPE_VOTING:{
            size_t l_tsd_size = 0;
            dap_chain_tx_tsd_t *l_item = (dap_chain_tx_tsd_t *)dap_chain_datum_tx_item_get(a_datum, NULL, (byte_t*)item + l_size, TX_ITEM_TYPE_TSD, &l_tsd_size);
            if (!l_item || !l_tsd_size)
                    break;
            dap_chain_datum_tx_voting_params_t *l_voting_params = dap_chain_datum_tx_voting_parse_tsd(a_datum);
            if (a_version == 1)
                dap_json_object_add(json_obj_item, "item type", dap_dap_json_object_new_string("VOTING"));
            dap_json_object_add(json_obj_item, a_version == 1 ? "Voting question" : "voting_question", dap_dap_json_object_new_string(l_voting_params->question));
            dap_json_object_add(json_obj_item, a_version == 1 ? "Answer options" : "answer_options", dap_dap_json_object_new_string(""));
            
            dap_list_t *l_temp = l_voting_params->options;
            uint8_t l_index = 0;
            while (l_temp) {
                dap_json_object_add(json_obj_item, dap_itoa(l_index), dap_dap_json_object_new_string((char *)l_temp->data));
                l_index++;
                l_temp = l_temp->next;
            }
            if (l_voting_params->voting_expire) {
                dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_voting_params->voting_expire);
                dap_json_object_add(json_obj_item, a_version == 1 ? "Voting expire" : "voting_expire", dap_dap_json_object_new_string(l_tmp_buf));                
            }
            if (l_voting_params->votes_max_count) {
                dap_json_object_add(json_obj_item, a_version == 1 ? "Votes max count" : "votes_max_count", dap_json_object_new_uint64(l_voting_params->votes_max_count));
            }
            if (a_version == 1) {
                dap_json_object_add(json_obj_item,"Changing vote is", l_voting_params->vote_changing_allowed ? dap_dap_json_object_new_string("available") : 
                                    dap_dap_json_object_new_string("not available"));
                l_voting_params->delegate_key_required ?
                    dap_json_object_add(json_obj_item, "Delegated key for participating in voting", dap_dap_json_object_new_string("required")) :
                    dap_json_object_add(json_obj_item, "Delegated key for participating in voting", dap_dap_json_object_new_string("not required"));  
            } else {
                dap_json_object_add_bool(json_obj_item,"changing_vote", l_voting_params->vote_changing_allowed);
                dap_json_object_add_bool(json_obj_item,"delegate_key_required", l_voting_params->delegate_key_required);   
            }

            dap_list_free_full(l_voting_params->options, NULL);
            DAP_DELETE(l_voting_params->question);
            DAP_DELETE(l_voting_params);
        } break;
        case TX_ITEM_TYPE_VOTE:{
            dap_chain_tx_vote_t *l_vote_item = (dap_chain_tx_vote_t *)item;
            const char *l_hash_str = dap_chain_hash_fast_to_str_static(&l_vote_item->voting_hash);
            if (a_version == 1)
                dap_json_object_add(json_obj_item, "item type", dap_dap_json_object_new_string("VOTE"));
            dap_json_object_add(json_obj_item, a_version == 1 ? "Voting hash" : "voting_hash", dap_dap_json_object_new_string(l_hash_str));
            dap_json_object_add(json_obj_item, a_version == 1 ? "Vote answer idx" : "vote_answer_idx", dap_json_object_new_uint64(l_vote_item->answer_idx));

        } break;
        default:
            if (a_version == 1)
                dap_json_object_add(json_obj_item, "item type", dap_dap_json_object_new_string("This transaction have unknown item type"));
            break;
        }
        dap_json_array_add(json_arr_items, json_obj_item);
    }
    dap_json_object_add(json_obj_out, a_version == 1 ? "ITEMS" : "items", json_arr_items);
    return true;
}

void s_token_dump_decl_json(dap_json_t  *a_obj_out, dap_chain_datum_token_t *a_token, size_t a_token_size, const char *a_hash_out_type, int a_version) {
    dap_json_object_add(a_obj_out, a_version == 1 ? "type" : "token_type", dap_dap_json_object_new_string("DECL"));
    switch (a_token->subtype) {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:{
            dap_json_object_add(a_obj_out, "subtype",dap_dap_json_object_new_string("PRIVATE"));
            dap_json_object_add(a_obj_out,"decimals",dap_json_object_new_uint64(a_token->header_private_decl.decimals));
            dap_json_object_add(a_obj_out, a_version == 1 ? "auth signs valid" : "auth_sig_valid", dap_json_object_new_uint64(a_token->signs_valid));
            dap_json_object_add(a_obj_out, a_version == 1 ? "auth signs total" : "auth_sig_total", dap_json_object_new_uint64(a_token->signs_total));
            dap_json_object_add(a_obj_out,"total_supply",dap_dap_json_object_new_string(dap_uint256_to_char(a_token->total_supply, NULL)));

            dap_chain_datum_token_flags_dump_to_json(a_obj_out, "flags",a_token->header_private_decl.flags);
            dap_datum_token_dump_tsd_to_json(a_obj_out, a_token, a_token_size, a_hash_out_type);
            size_t l_certs_field_size = a_token_size - sizeof(*a_token) - a_token->header_private_update.tsd_total_size;
            dap_chain_datum_token_certs_dump_to_json(a_obj_out,a_token->tsd_n_signs + a_token->header_private_update.tsd_total_size,
                                                     l_certs_field_size, a_hash_out_type, a_version);
        } break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE: {
            dap_json_object_add(a_obj_out,"subtype",dap_dap_json_object_new_string("CF20"));
            dap_json_object_add(a_obj_out,"decimals",dap_json_object_new_uint64(a_token->header_native_decl.decimals));
            dap_json_object_add(a_obj_out, a_version == 1 ? "auth signs valid" : "auth_sig_valid", dap_json_object_new_uint64(a_token->signs_valid));
            dap_json_object_add(a_obj_out, a_version == 1 ? "auth signs total" : "auth_sig_total", dap_json_object_new_uint64(a_token->signs_total));
            dap_json_object_add(a_obj_out,"total_supply",dap_dap_json_object_new_string(dap_uint256_to_char(a_token->total_supply, NULL)));
            dap_chain_datum_token_flags_dump_to_json(a_obj_out, "flags", a_token->header_native_decl.flags);
            dap_datum_token_dump_tsd_to_json(a_obj_out, a_token, a_token_size, a_hash_out_type);
            size_t l_certs_field_size = a_token_size - sizeof(*a_token) - a_token->header_native_decl.tsd_total_size;
            dap_chain_datum_token_certs_dump_to_json(a_obj_out, a_token->tsd_n_signs + a_token->header_native_decl.tsd_total_size,
                                                     l_certs_field_size, a_hash_out_type, a_version);
        } break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC: {
            dap_chain_addr_t l_premine_addr = a_token->header_public.premine_address;
            dap_json_object_add(a_obj_out,"subtype",dap_dap_json_object_new_string("PUBLIC"));
            dap_json_object_add(a_obj_out,"premine_supply", dap_dap_json_object_new_string(dap_uint256_to_char(a_token->header_public.premine_supply, NULL)));
            dap_json_object_add(a_obj_out,"premine_address", dap_dap_json_object_new_string(dap_chain_addr_to_str_static(&l_premine_addr)));

            dap_chain_datum_token_flags_dump_to_json(a_obj_out, "flags", a_token->header_public.flags);
        } break;
    }
}

void s_token_dump_update_json(dap_json_t  *a_obj_out, dap_chain_datum_token_t *a_token, size_t a_token_size, const char *a_hash_out_type, bool a_verbose, int a_version) {
    if (a_verbose) dap_json_object_add(a_obj_out, a_version == 1 ? "type" : "token_type", dap_dap_json_object_new_string("UPDATE"));
    switch (a_token->subtype) {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE: {
            if (a_verbose) dap_json_object_add(a_obj_out,"subtype",dap_dap_json_object_new_string("PRIVATE"));
            dap_json_object_add(a_obj_out, a_version == 1 ? "total_sign" : "total_sig_count", dap_json_object_new_uint64(a_token->signs_total));

            dap_datum_token_dump_tsd_to_json(a_obj_out, a_token, a_token_size, a_hash_out_type);
            size_t l_certs_field_size = a_token_size - sizeof(*a_token) - a_token->header_private_update.tsd_total_size;
            dap_chain_datum_token_certs_dump_to_json(a_obj_out, a_token->tsd_n_signs + a_token->header_private_update.tsd_total_size,
                                                     l_certs_field_size, a_hash_out_type, a_version);
        } break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE: {
            if (a_verbose) dap_json_object_add(a_obj_out,"subtype", dap_dap_json_object_new_string("CF20"));
            dap_json_object_add(a_obj_out, a_version == 1 ? "total_sign" : "total_sig_count", dap_json_object_new_uint64(a_token->signs_total));

            dap_datum_token_dump_tsd_to_json(a_obj_out, a_token, a_token_size, a_hash_out_type);
            size_t l_certs_field_size = a_token_size - sizeof(*a_token) - a_token->header_native_update.tsd_total_size;
            dap_chain_datum_token_certs_dump_to_json(a_obj_out, a_token->tsd_n_signs + a_token->header_native_update.tsd_total_size,
                                                     l_certs_field_size, a_hash_out_type, a_version);
        } break;
    }
}

/**
 * @brief dap_chain_net_dump_datum
 * process datum verification process. Can be:
 * if DAP_CHAIN_DATUM_TX, called dap_ledger_tx_add_check
 * if DAP_CHAIN_DATUM_TOKEN, called dap_ledger_token_add_check
 * if DAP_CHAIN_DATUM_TOKEN_EMISSION, called dap_ledger_token_emission_add_check
 * @param a_obj_out
 * @param a_datum
 */
void dap_chain_datum_dump_json(dap_json_t* a_json_arr_reply, dap_json_t *a_obj_out, dap_chain_datum_t *a_datum, const char *a_hash_out_type, dap_chain_net_id_t a_net_id, bool a_verbose, int a_version)
{
    if( a_datum == NULL){
        dap_json_rpc_error_add(a_json_arr_reply, -1,"==Datum is NULL");
        return;
    }
    dap_json_t * json_obj_datum = dap_json_object_new();
    dap_hash_fast_t l_datum_hash;
    dap_chain_datum_calc_hash(a_datum, &l_datum_hash);
    const char *l_hash_str = dap_strcmp(a_hash_out_type, "hex")
            ? dap_enc_base58_encode_hash_to_str_static(&l_datum_hash)
            : dap_chain_hash_fast_to_str_static(&l_datum_hash);
    if (a_version != 1)
        dap_json_object_add(json_obj_datum, "datum_type", dap_dap_json_object_new_string(dap_datum_type_to_str(a_datum->header.type_id)));
    switch (a_datum->header.type_id) {
        case DAP_CHAIN_DATUM_TOKEN: {
            size_t l_token_size = a_datum->header.data_size;
            dap_chain_datum_token_t * l_token = dap_chain_datum_token_read(a_datum->data, &l_token_size);
            if(l_token_size < sizeof(dap_chain_datum_token_t)){
                dap_json_rpc_error_add(a_json_arr_reply, -2,"==Datum has incorrect size. Only %zu, while at least %zu is expected\n",
                                         l_token_size, sizeof(dap_chain_datum_token_t));
                DAP_DEL_Z(l_token);
                return;
            }
            if (a_version == 1)
                dap_json_object_add(json_obj_datum, "=== Datum Token Declaration ===", dap_dap_json_object_new_string(""));
            dap_json_object_add(json_obj_datum, a_version == 1 ? "hash" : "datum_hash", dap_dap_json_object_new_string(l_hash_str));
            if (l_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE || a_verbose) {
                dap_json_object_add(json_obj_datum, "ticker", dap_dap_json_object_new_string(l_token->ticker));
            }
            dap_json_object_add(json_obj_datum,"size",dap_json_object_new_uint64(l_token_size));
            dap_json_object_add_int(json_obj_datum,"version", l_token->version);

            switch (l_token->type) {
                case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL:
                    s_token_dump_decl_json(json_obj_datum, l_token, l_token_size, a_hash_out_type, a_version);
                    break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE:
                    s_token_dump_update_json(json_obj_datum, l_token, l_token_size, a_hash_out_type, false, a_version);
                break;
                default:
                    dap_json_object_add(json_obj_datum, a_version == 1 ? "type" : "token_type", dap_dap_json_object_new_string(a_version == 1 ? "UNKNOWN" : "UNDEFINED"));
                    break;
            }
            if (l_token->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE ) {
                dap_json_object_add(json_obj_datum,"subtype", dap_dap_json_object_new_string("SIMPLE"));
                dap_json_object_add(json_obj_datum,"decimals", dap_json_object_new_uint64(l_token->header_simple.decimals));
                dap_json_object_add(json_obj_datum, a_version == 1 ? "sign_total" : "signs_total", dap_json_object_new_uint64(l_token->signs_total));
                dap_json_object_add(json_obj_datum, a_version == 1 ? "sign_valid" : "signs_valid", dap_json_object_new_uint64(l_token->signs_valid));
                dap_json_object_add(json_obj_datum,"total_supply",dap_dap_json_object_new_string(dap_uint256_to_char(l_token->total_supply, NULL)));
                
                size_t l_certs_field_size = l_token_size - sizeof(*l_token);
                dap_chain_datum_token_certs_dump_to_json(json_obj_datum, l_token->tsd_n_signs,
                                                 l_certs_field_size, a_hash_out_type, a_version);
            }
            DAP_DELETE(l_token);
        } break;
        case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
            size_t l_emission_size = a_datum->header.data_size;
            dap_chain_datum_token_emission_t *l_emission = dap_chain_datum_emission_read(a_datum->data, &l_emission_size);
            const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_emission->hdr.value, &l_coins_str);
            dap_json_object_add(json_obj_datum, a_version == 1 ? "emission hash" : "emission_hash", dap_dap_json_object_new_string(l_hash_str));
            dap_json_object_add(json_obj_datum, "coins", dap_dap_json_object_new_string(l_coins_str));
            dap_json_object_add(json_obj_datum, "value", dap_dap_json_object_new_string(l_value_str));
            dap_json_object_add(json_obj_datum, "ticker", dap_dap_json_object_new_string(l_emission->hdr.ticker));
            dap_json_object_add(json_obj_datum, "type", dap_dap_json_object_new_string(dap_chain_datum_emission_type_str(l_emission->hdr.type)));
            dap_json_object_add(json_obj_datum, "version", dap_json_object_new_uint64(l_emission->hdr.version));
            dap_json_object_add(json_obj_datum, a_version == 1 ? "to addr" : "to_addr", dap_dap_json_object_new_string(dap_chain_addr_to_str_static(&(l_emission->hdr.address))));

            switch (l_emission->hdr.type) {
            case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH:
                dap_json_object_add(json_obj_datum,"sig_count", dap_json_object_new_uint64(l_emission->data.type_auth.signs_count));
                dap_json_object_add(json_obj_datum,"tsd_total_size", dap_json_object_new_uint64(l_emission->data.type_auth.tsd_total_size));

                if (  ( (void *) l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size) >
                      ((void *) l_emission + l_emission_size) )
                {
                    log_it(L_ERROR, "Illformed DATUM type %d, TSD section is out-of-buffer (%" DAP_UINT64_FORMAT_U " vs %zu)",
                        l_emission->hdr.type, l_emission->data.type_auth.tsd_total_size, l_emission_size);
                    dap_json_rpc_error_add(a_json_arr_reply, -3,"Skip incorrect or illformed DATUM");
                    break;
                }
                dap_chain_datum_token_certs_dump_to_json(json_obj_datum, l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size,
                                                l_emission->data.type_auth.tsd_n_signs_size - l_emission->data.type_auth.tsd_total_size, a_hash_out_type, a_version);
                break;
            case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ALGO:
                dap_json_object_add(json_obj_datum,"codename",dap_dap_json_object_new_string(l_emission->data.type_algo.codename));
                break;
            case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_SMART_CONTRACT: {
                char l_time_str[32];
                char l_flags[50] = {};
                // get time of create datum
                if(dap_time_to_str_rfc822(l_time_str, sizeof(l_time_str), l_emission->data.type_presale.lock_time) < 1)
                        l_time_str[0] = '\0';                        
                snprintf(l_flags, 50, "0x%x", l_emission->data.type_presale.flags);
                dap_json_object_add(json_obj_datum,"flags", dap_dap_json_object_new_string(l_flags));
                dap_json_object_add(json_obj_datum,"lock_time", dap_dap_json_object_new_string(l_time_str));
                dap_json_object_add(json_obj_datum,"addr", dap_dap_json_object_new_string(dap_chain_addr_to_str_static(&l_emission->data.type_presale.addr)));                
            }
            case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ATOM_OWNER:
            case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_UNDEFINED:
            default:
                break;
            }
            DAP_DELETE(l_emission);
        } break;
        case DAP_CHAIN_DATUM_TX: {
            dap_ledger_t *l_ledger = dap_chain_net_by_id(a_net_id)->pub.ledger;
            const char *l_tx_token_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_datum_hash);
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*)a_datum->data;
            dap_chain_datum_dump_tx_json(a_json_arr_reply, l_tx, l_tx_token_ticker, json_obj_datum, a_hash_out_type, &l_datum_hash, a_net_id, a_version);
        } break;
        case DAP_CHAIN_DATUM_DECREE:{
            dap_chain_datum_decree_t *l_decree = (dap_chain_datum_decree_t *)a_datum->data;
            size_t l_decree_size = dap_chain_datum_decree_get_size(l_decree);
            if (a_version == 1)
                dap_json_object_add(json_obj_datum, "=== Datum decree ===", dap_dap_json_object_new_string(""));
            dap_json_object_add(json_obj_datum, a_version == 1 ? "hash" : "datum_hash", dap_dap_json_object_new_string(l_hash_str));
            dap_json_object_add(json_obj_datum,"size",dap_json_object_new_uint64(l_decree_size));
            dap_chain_datum_decree_dump_json(json_obj_datum, l_decree, l_decree_size, a_hash_out_type, a_version);
        } break;
        case DAP_CHAIN_DATUM_ANCHOR:{
            dap_chain_datum_anchor_t *l_anchor = (dap_chain_datum_anchor_t *)a_datum->data;
            size_t l_anchor_size = sizeof(dap_chain_datum_anchor_t) + l_anchor->header.data_size + l_anchor->header.signs_size;
            if (a_version == 1)
                dap_json_object_add(json_obj_datum, "=== Datum anchor ===", dap_dap_json_object_new_string(""));
            dap_json_object_add(json_obj_datum, a_version == 1 ? "hash" : "datum_hash", dap_dap_json_object_new_string(l_hash_str));
            dap_json_object_add(json_obj_datum,"size",dap_json_object_new_uint64(l_anchor_size));
            dap_hash_fast_t l_decree_hash = { };
            dap_chain_datum_anchor_get_hash_from_data(l_anchor, &l_decree_hash);
            l_hash_str = dap_chain_hash_fast_to_str_static(&l_decree_hash);
            dap_json_object_add(json_obj_datum, a_version == 1 ? "decree hash" : "decree_hash", dap_dap_json_object_new_string(l_hash_str));
            dap_chain_datum_anchor_certs_dump_json(json_obj_datum,l_anchor->data_n_sign + l_anchor->header.data_size, l_anchor->header.signs_size, a_hash_out_type, a_version);
        } break;
    }  
    dap_json_object_add(a_obj_out, a_version == 1 ? "Datum" : "datum", json_obj_datum);  
}
