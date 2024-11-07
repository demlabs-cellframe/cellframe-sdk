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

#include "dap_common.h"
#include "dap_time.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_datum_anchor.h"
#include "dap_chain_datum_tx_voting.h"
#include "dap_chain_datum_hashtree_roots.h"
#include "dap_enc_base58.h"
#include "dap_sign.h"
#include "dap_tsd.h"

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
   memcpy(l_datum->data, a_data, (uint32_t)a_data_size);
   return  l_datum;
}
void dap_datum_token_dump_tsd_to_json(json_object * json_obj_out, dap_chain_datum_token_t *a_token, size_t a_token_size, const char *a_hash_out_type)
{
    dap_tsd_t *l_tsd_begin = dap_chain_datum_token_tsd_get(a_token, a_token_size);
    if (!l_tsd_begin) {
        json_object_object_add(json_obj_out, "status", json_object_new_string("<CORRUPTED TSD SECTION>"));
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
            char *l_balance = dap_chain_balance_print(_dap_tsd_get_scalar(l_tsd, &l_t));
            json_object_object_add(json_obj_out, "total_supply", json_object_new_string(l_balance));
            DAP_DELETE(l_balance);
            continue;
        }
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID: {
            uint16_t l_t = 0;
            json_object_object_add(json_obj_out, "total_signs_valid", json_object_new_int(_dap_tsd_get_scalar(l_tsd, &l_t)));
            continue;
        }
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_ADD:
            if(l_tsd->size >= sizeof(dap_pkey_t)) {
                    char *l_hash_str;
                    dap_pkey_t *l_pkey = (dap_pkey_t*)l_tsd->data;
                    dap_hash_fast_t l_hf = { };
                    if (!dap_pkey_get_hash(l_pkey, &l_hf)) {
                        json_object_object_add(json_obj_out, "total_pkeys_add", json_object_new_string("<WRONG CALCULATION FINGERPRINT>"));
                    } else {
                        if (!dap_strcmp(a_hash_out_type, "hex") || !dap_strcmp(a_hash_out_type, "content_hash"))
                            l_hash_str = dap_chain_hash_fast_to_str_new(&l_hf);
                        else
                            l_hash_str = dap_enc_base58_encode_hash_to_str(&l_hf);
                        json_object_object_add(json_obj_out, "total_pkeys_add", json_object_new_string(l_hash_str));
                        DAP_DELETE(l_hash_str);
                    }
            } else
                    json_object_object_add(json_obj_out, "total_pkeys_add_with_wrong_size", json_object_new_int(l_tsd->size));
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_REMOVE:
            if(l_tsd->size == sizeof(dap_chain_hash_fast_t) ){
                    char *l_hash_str = (!dap_strcmp(a_hash_out_type,"hex")|| !dap_strcmp(a_hash_out_type, "content_hash"))
                                           ? dap_chain_hash_fast_to_str_new((dap_chain_hash_fast_t*) l_tsd->data)
                                           : dap_enc_base58_encode_hash_to_str((dap_chain_hash_fast_t*) l_tsd->data);
                    json_object_object_add(json_obj_out, "total_pkeys_remove", json_object_new_string(l_hash_str));
                    DAP_DELETE( l_hash_str );
            } else
                    json_object_object_add(json_obj_out, "total_pkeys_remove_with_wrong_size", json_object_new_int(l_tsd->size));
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK: {
            char *balance = NULL;
            dap_chain_datum_token_tsd_delegate_from_stake_lock_t *l_tsd_section = _dap_tsd_get_object(l_tsd, dap_chain_datum_token_tsd_delegate_from_stake_lock_t);
            balance = dap_chain_balance_to_coins(l_tsd_section->emission_rate);
            json_object_object_add(json_obj_out, "ticker_token_from", json_object_new_string(l_tsd_section->ticker_token_from));
            json_object_object_add(json_obj_out, "emission_rate", json_object_new_string(balance));
            DAP_DEL_Z(balance);
        }continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD  :
                json_object_object_add(json_obj_out, "datum_type_allowed_add", json_object_new_string(dap_tsd_get_string_const(l_tsd)));
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_REMOVE  :
            json_object_object_add(json_obj_out, "datum_type_allowed_remove", json_object_new_string(dap_tsd_get_string_const(l_tsd)));
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_ADD  :
            json_object_object_add(json_obj_out, "datum_type_blocked_add", json_object_new_string(dap_tsd_get_string_const(l_tsd)));
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_REMOVE:
            json_object_object_add(json_obj_out, "datum_type_blocked_remove", json_object_new_string(dap_tsd_get_string_const(l_tsd)));
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD: {
                dap_chain_addr_t *l_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
                json_object_object_add(json_obj_out, "tx_sender_allowed_add", json_object_new_string(dap_chain_addr_to_str_static(l_addr)));
            } continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_REMOVE:{
                dap_chain_addr_t *l_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
                json_object_object_add(json_obj_out, "tx_sender_allowed_remove", json_object_new_string(dap_chain_addr_to_str_static(l_addr)));
            } continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD: {
                dap_chain_addr_t *l_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
                json_object_object_add(json_obj_out, "tx_sender_blocked_add", json_object_new_string(dap_chain_addr_to_str_static(l_addr)));
            } continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_REMOVE: {
                dap_chain_addr_t *l_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
                json_object_object_add(json_obj_out, "tx_sender_blocked_remove", json_object_new_string(dap_chain_addr_to_str_static(l_addr)));
            } continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD: {
                dap_chain_addr_t *l_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
                json_object_object_add(json_obj_out, "tx_receiver_allowed_add", json_object_new_string(dap_chain_addr_to_str_static(l_addr)));
            } continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_REMOVE: {
                dap_chain_addr_t *l_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
                json_object_object_add(json_obj_out, "tx_receiver_allowed", json_object_new_string(dap_chain_addr_to_str_static(l_addr)));
            } continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD: {
                dap_chain_addr_t *l_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
                json_object_object_add(json_obj_out, "tx_receiver_blocked_add", json_object_new_string(dap_chain_addr_to_str_static(l_addr)));
            } continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_REMOVE: {
                dap_chain_addr_t *l_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
                json_object_object_add(json_obj_out, "tx_receiver_blocked_remove", json_object_new_string(dap_chain_addr_to_str_static(l_addr)));
            } continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TOKEN_DESCRIPTION:
            json_object_object_add(json_obj_out, "description", json_object_new_string(dap_tsd_get_string_const(l_tsd)));
            continue;
        default: {
                char l_tsd_type_char[50] = {};
                snprintf(l_tsd_type_char, 50, "<0x%04hX>", l_tsd->type);
                json_object_object_add(json_obj_out, "tsd_type", json_object_new_string(l_tsd_type_char));
                json_object_object_add(json_obj_out, "tsd_size", json_object_new_int(l_tsd->size));
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
bool dap_chain_datum_dump_tx_json(json_object* a_json_arr_reply,
                             dap_chain_datum_tx_t *a_datum,
                             const char *a_ticker,
                             json_object* json_obj_out,
                             const char *a_hash_out_type,
                             dap_hash_fast_t *a_tx_hash,
                             dap_chain_net_id_t a_net_id)
{
    bool l_is_first = false;
    dap_chain_tx_in_t *l_in_item = (dap_chain_tx_in_t *)dap_chain_datum_tx_item_get(a_datum, NULL, NULL, TX_ITEM_TYPE_IN, NULL);
    if (l_in_item && dap_hash_fast_is_blank(&l_in_item->header.tx_prev_hash))
        l_is_first = true;
    char l_tmp_buf[DAP_TIME_STR_SIZE];
    const char *l_hash_str = dap_strcmp(a_hash_out_type, "hex")
            ? dap_enc_base58_encode_hash_to_str_static(a_tx_hash)
            : dap_chain_hash_fast_to_str_static(a_tx_hash);
    json_object* json_arr_items = json_object_new_array();
    dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, a_datum->header.ts_created);
    l_is_first ? 
    json_object_object_add(json_obj_out, "first transaction", json_object_new_string("emit")):
    json_object_object_add(json_obj_out, "first transaction", json_object_new_string(""));
    json_object_object_add(json_obj_out, "hash", json_object_new_string(l_hash_str));
    json_object_object_add(json_obj_out, "tx created", json_object_new_string(l_tmp_buf));
    json_object_object_add(json_obj_out, "token ticker", a_ticker ? json_object_new_string(a_ticker) : json_object_new_string(""));
    //json_object_array_add(json_arr_items, json_obj_tx);

    dap_hash_fast_t l_hash_tmp = { };
    byte_t *item; size_t l_size;
    TX_ITEM_ITER_TX(item, l_size, a_datum) {
        json_object* json_obj_item = json_object_new_object();
        switch (*item) {
        case TX_ITEM_TYPE_IN:
            l_hash_tmp = ((dap_chain_tx_in_t*)item)->header.tx_prev_hash;
            l_hash_str = !dap_hash_fast_is_blank(&l_hash_tmp)
                ? dap_strcmp(a_hash_out_type, "hex") ? dap_enc_base58_encode_hash_to_str_static(&l_hash_tmp) : dap_chain_hash_fast_to_str_static(&l_hash_tmp)
                : "BLANK";
            json_object_object_add(json_obj_item,"item type", json_object_new_string("IN"));
            json_object_object_add(json_obj_item,"Tx prev hash", json_object_new_string(l_hash_str));
            json_object_object_add(json_obj_item,"Tx out prev idx", json_object_new_uint64(((dap_chain_tx_in_t*)item)->header.tx_out_prev_idx));
            break;
        case TX_ITEM_TYPE_OUT_OLD: {
            const char *l_value_str = dap_uint256_to_char(
                dap_chain_uint256_from(((dap_chain_tx_out_old_t*)item)->header.value), NULL );
            json_object_object_add(json_obj_item,"item type", json_object_new_string("OUT OLD"));
            json_object_object_add(json_obj_item,"Value", json_object_new_uint64(((dap_chain_tx_out_old_t*)item)->header.value));
            json_object_object_add(json_obj_item,"Address", json_object_new_string(dap_chain_addr_to_str_static(&((dap_chain_tx_out_old_t*)item)->addr)));
        } break;
        case TX_ITEM_TYPE_OUT: { // 256
            const char *l_coins_str,
                    *l_value_str = dap_uint256_to_char(((dap_chain_tx_out_t*)item)->header.value, &l_coins_str),
                    *l_addr_str = dap_chain_addr_to_str_static(&((dap_chain_tx_out_t*)item)->addr);
            json_object_object_add(json_obj_item,"item type", json_object_new_string("OUT"));
            json_object_object_add(json_obj_item,"Coins", json_object_new_string(l_coins_str));
            json_object_object_add(json_obj_item,"Value", json_object_new_string(l_value_str));
            json_object_object_add(json_obj_item,"Address", json_object_new_string(l_addr_str));            
        } break;
        case TX_ITEM_TYPE_IN_EMS: {
            char l_tmp_buff[70];
            l_hash_tmp = ((dap_chain_tx_in_ems_t*)item)->header.token_emission_hash;
            l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str_static(&l_hash_tmp)
                    : dap_chain_hash_fast_to_str_static(&l_hash_tmp);
            json_object_object_add(json_obj_item,"item type", json_object_new_string("IN_EMS"));
            json_object_object_add(json_obj_item,"ticker", json_object_new_string(((dap_chain_tx_in_ems_t*)item)->header.ticker));
            json_object_object_add(json_obj_item,"token_emission_hash", json_object_new_string(l_hash_str));
            snprintf(l_tmp_buff, sizeof(l_tmp_buff), "0x%016"DAP_UINT64_FORMAT_x"",((dap_chain_tx_in_ems_t*)item)->header.token_emission_chain_id.uint64);
            json_object_object_add(json_obj_item,"token_emission_chain_id", json_object_new_string(l_tmp_buff));
        } break;

        case TX_ITEM_TYPE_IN_REWARD: {
            l_hash_tmp = ((dap_chain_tx_in_reward_t *)item)->block_hash;
            l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str_static(&l_hash_tmp)
                    : dap_chain_hash_fast_to_str_static(&l_hash_tmp);
            json_object_object_add(json_obj_item,"item type", json_object_new_string("IN_REWARD"));
            json_object_object_add(json_obj_item,"block_hash", json_object_new_string(l_hash_str));
        } break;

        case TX_ITEM_TYPE_SIG: {
            dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t*)item);
            json_object_object_add(json_obj_item,"item type", json_object_new_string("SIG"));
            dap_sign_get_information_json(a_json_arr_reply, l_sign, json_obj_item, a_hash_out_type);
            dap_chain_addr_t l_sender_addr;
            dap_chain_addr_fill_from_sign(&l_sender_addr, l_sign, a_net_id);
            json_object_object_add(json_obj_item,"Sender addr", json_object_new_string(dap_chain_addr_to_str_static(&l_sender_addr)));            
        } break;
        case TX_ITEM_TYPE_RECEIPT: {
            const char *l_coins_str, *l_value_str = dap_uint256_to_char(((dap_chain_datum_tx_receipt_t*)item)->receipt_info.value_datoshi, &l_coins_str);
            json_object_object_add(json_obj_item,"item type", json_object_new_string("RECEIPT"));
            json_object_object_add(json_obj_item,"size", json_object_new_uint64(((dap_chain_datum_tx_receipt_t*)item)->size));
            json_object_object_add(json_obj_item,"ext size", json_object_new_uint64(((dap_chain_datum_tx_receipt_t*)item)->exts_size));
            json_object_object_add(json_obj_item,"INFO", json_object_new_string(""));
            json_object_object_add(json_obj_item,"units", json_object_new_uint64(((dap_chain_datum_tx_receipt_t*)item)->receipt_info.units));
            json_object_object_add(json_obj_item,"uid", json_object_new_uint64(((dap_chain_datum_tx_receipt_t*)item)->receipt_info.srv_uid.uint64));
            json_object_object_add(json_obj_item,"units type", json_object_new_string(dap_chain_srv_unit_enum_to_str(((dap_chain_datum_tx_receipt_t*)item)->receipt_info.units_type.enm)));
            json_object_object_add(json_obj_item,"coins", json_object_new_string(l_coins_str));
            json_object_object_add(json_obj_item,"value", json_object_new_string(l_value_str));

            json_object_object_add(json_obj_item,"Exts",json_object_new_string(""));                         
            switch ( ((dap_chain_datum_tx_receipt_t*)item)->exts_size ) {
            case (sizeof(dap_sign_t) * 2): {
                dap_sign_t *l_client = (dap_sign_t*)( ((dap_chain_datum_tx_receipt_t*)item)->exts_n_signs + sizeof(dap_sign_t) );
                json_object_object_add(json_obj_item,"Client", json_object_new_string(""));
                dap_sign_get_information_json(a_json_arr_reply, l_client, json_obj_item, a_hash_out_type);                
            }
            case (sizeof(dap_sign_t)): {
                dap_sign_t *l_provider = (dap_sign_t*)( ((dap_chain_datum_tx_receipt_t*)item)->exts_n_signs );
                json_object_object_add(json_obj_item,"Provider", json_object_new_string(""));
                dap_sign_get_information_json(a_json_arr_reply, l_provider,json_obj_item, a_hash_out_type);
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
            json_object_object_add(json_obj_item,"item type", json_object_new_string("PKey"));
            json_object_object_add(json_obj_item,"PKey", json_object_new_string(""));
            json_object_object_add(json_obj_item,"SIG type", json_object_new_string(dap_sign_type_to_str(((dap_chain_tx_pkey_t*)item)->header.sig_type)));
            json_object_object_add(json_obj_item,"SIG size", json_object_new_uint64(((dap_chain_tx_pkey_t*)item)->header.sig_size));
            json_object_object_add(json_obj_item,"Sequence number", json_object_new_uint64(((dap_chain_tx_pkey_t*)item)->seq_no));
            json_object_object_add(json_obj_item,"Key", json_object_new_string(""));
            json_object_object_add(json_obj_item,"Type", json_object_new_string(dap_pkey_type_to_str(l_pkey->header.type)));
            json_object_object_add(json_obj_item,"Size", json_object_new_uint64(l_pkey->header.size));
            json_object_object_add(json_obj_item,"Hash", json_object_new_string(l_hash_str));

        } break;
        case TX_ITEM_TYPE_TSD: {
            json_object_object_add(json_obj_item,"item type", json_object_new_string("TSD data"));
            json_object_object_add(json_obj_item,"type", json_object_new_uint64(((dap_chain_tx_tsd_t*)item)->header.type));
            json_object_object_add(json_obj_item,"size", json_object_new_uint64(((dap_chain_tx_tsd_t*)item)->header.size));            
        } break;
        case TX_ITEM_TYPE_IN_COND:
            json_object_object_add(json_obj_item,"item type", json_object_new_string("IN COND"));
            l_hash_tmp = ((dap_chain_tx_in_cond_t*)item)->header.tx_prev_hash;
            l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str_static(&l_hash_tmp)
                    : dap_chain_hash_fast_to_str_static(&l_hash_tmp);
            json_object_object_add(json_obj_item,"Receipt_idx", json_object_new_int(((dap_chain_tx_in_cond_t*)item)->header.receipt_idx));
            json_object_object_add(json_obj_item,"Tx_prev_hash", json_object_new_string(l_hash_str));
            json_object_object_add(json_obj_item,"Tx_out_prev_idx", json_object_new_uint64(((dap_chain_tx_in_cond_t*)item)->header.tx_out_prev_idx));
            break;
        case TX_ITEM_TYPE_OUT_COND: {
            char l_tmp_buff[70];
            json_object_object_add(json_obj_item,"item type", json_object_new_string("OUT COND"));
            const char *l_coins_str, *l_value_str = dap_uint256_to_char(((dap_chain_tx_out_cond_t*)item)->header.value, &l_coins_str);
            dap_time_t l_ts_exp = ((dap_chain_tx_out_cond_t*)item)->header.ts_expires;
            dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_ts_exp);
            json_object_object_add(json_obj_item,"Header", json_object_new_string(""));
            json_object_object_add(json_obj_item,"ts_expires", l_ts_exp ? json_object_new_string(l_tmp_buf) : json_object_new_string("never"));
            json_object_object_add(json_obj_item,"coins", json_object_new_string(l_coins_str));
            json_object_object_add(json_obj_item,"value", json_object_new_string(l_value_str));
            json_object_object_add(json_obj_item,"subtype", json_object_new_string(dap_chain_tx_out_cond_subtype_to_str(((dap_chain_tx_out_cond_t*)item)->header.subtype)));
            snprintf(l_tmp_buff, sizeof(l_tmp_buff), "0x%016"DAP_UINT64_FORMAT_x"",((dap_chain_tx_out_cond_t*)item)->header.srv_uid.uint64);
            json_object_object_add(json_obj_item,"uid", json_object_new_string(l_tmp_buff));
            switch (((dap_chain_tx_out_cond_t*)item)->header.subtype) {
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY: {
                    const char *l_coins_str, *l_value_str =
                        dap_uint256_to_char( ((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.unit_price_max_datoshi, &l_coins_str );
                    l_hash_tmp = ((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.pkey_hash;
                    l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                            ? dap_enc_base58_encode_hash_to_str_static(&l_hash_tmp)
                            : dap_chain_hash_fast_to_str_static(&l_hash_tmp);
                    snprintf(l_tmp_buff, sizeof(l_tmp_buff), "0x%08x",((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.unit.uint32);
                    json_object_object_add(json_obj_item,"unit", json_object_new_string(l_tmp_buff));
                    json_object_object_add(json_obj_item,"pkey", json_object_new_string(l_hash_str));
                    json_object_object_add(json_obj_item,"max price(coins)", json_object_new_string(l_coins_str));
                    json_object_object_add(json_obj_item,"max price(value)", json_object_new_string(l_value_str));

                } break;
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE: {
                    dap_chain_node_addr_t *l_signer_node_addr = &((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake_pos_delegate.signer_node_addr;
                    dap_chain_addr_t *l_signing_addr = &((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake_pos_delegate.signing_addr;
                    l_hash_tmp = l_signing_addr->data.hash_fast;
                    l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                            ? dap_enc_base58_encode_hash_to_str_static(&l_hash_tmp)
                            : dap_chain_hash_fast_to_str_static(&l_hash_tmp);
                    json_object_object_add(json_obj_item,"signing_addr", json_object_new_string(dap_chain_addr_to_str_static(l_signing_addr)));
                    json_object_object_add(json_obj_item,"with pkey hash", json_object_new_string(l_hash_str));                    
                    snprintf(l_tmp_buff, sizeof(l_tmp_buff), ""NODE_ADDR_FP_STR"",NODE_ADDR_FP_ARGS(l_signer_node_addr));
                    json_object_object_add(json_obj_item,"signer_node_addr", json_object_new_string(l_tmp_buff));
                    
                } break;
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE: {
                    const char *l_rate_str, *l_tmp_str =
                        dap_uint256_to_char( (((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.rate), &l_rate_str );
                    snprintf(l_tmp_buff,sizeof(l_tmp_buff),"0x%016"DAP_UINT64_FORMAT_x"",((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.buy_net_id.uint64);
                    json_object_object_add(json_obj_item,"net id", json_object_new_string(l_tmp_buff));
                    json_object_object_add(json_obj_item,"buy_token", json_object_new_string(((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.buy_token));
                    json_object_object_add(json_obj_item,"rate", json_object_new_string(l_rate_str));
                } break;
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK: {
                    dap_time_t l_ts_unlock = ((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake_lock.time_unlock;
                    dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_ts_unlock);
                    json_object_object_add(json_obj_item,"time_unlock", json_object_new_string(l_tmp_buf));
                } break;
                default: break;
            }
        } break;
        case TX_ITEM_TYPE_OUT_EXT: {
            const char *l_coins_str, *l_value_str = dap_uint256_to_char( ((dap_chain_tx_out_ext_t*)item)->header.value, &l_coins_str );
            json_object_object_add(json_obj_item,"item type", json_object_new_string("OUT EXT"));
            json_object_object_add(json_obj_item,"Addr", json_object_new_string(dap_chain_addr_to_str_static(&((dap_chain_tx_out_ext_t*)item)->addr)));
            json_object_object_add(json_obj_item,"Token", json_object_new_string(((dap_chain_tx_out_ext_t*)item)->token));
            json_object_object_add(json_obj_item,"Coins", json_object_new_string(l_coins_str));
            json_object_object_add(json_obj_item,"Value", json_object_new_string(l_value_str));
            
        } break;
        case TX_ITEM_TYPE_VOTING:{
            size_t l_tsd_size = 0;
            dap_chain_tx_tsd_t *l_item = (dap_chain_tx_tsd_t *)dap_chain_datum_tx_item_get(a_datum, NULL, (byte_t*)item + l_size, TX_ITEM_TYPE_TSD, &l_tsd_size);
            if (!l_item || !l_tsd_size)
                    break;
            dap_chain_datum_tx_voting_params_t *l_voting_params = dap_chain_voting_parse_tsd(a_datum);
            json_object_object_add(json_obj_item,"item type", json_object_new_string("VOTING"));
            json_object_object_add(json_obj_item,"Voting question", json_object_new_string(l_voting_params->voting_question));
            json_object_object_add(json_obj_item,"Answer options", json_object_new_string(""));
            
            dap_list_t *l_temp = l_voting_params->answers_list;
            uint8_t l_index = 0;
            while (l_temp) {
                json_object_object_add(json_obj_item, dap_itoa(l_index), json_object_new_string((char *)l_temp->data));
                l_index++;
                l_temp = l_temp->next;
            }
            if (l_voting_params->voting_expire) {
                dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_voting_params->voting_expire);
                json_object_object_add(json_obj_item,"Voting expire", json_object_new_string(l_tmp_buf));                
            }
            if (l_voting_params->votes_max_count) {
                json_object_object_add(json_obj_item, "Votes max count", json_object_new_uint64(l_voting_params->votes_max_count));
            }
            json_object_object_add(json_obj_item,"Changing vote is", l_voting_params->vote_changing_allowed ? json_object_new_string("available") : 
                                    json_object_new_string("not available"));
            l_voting_params->delegate_key_required ? 
                json_object_object_add(json_obj_item,"Delegated key for participating in voting", json_object_new_string("required")):
                json_object_object_add(json_obj_item,"Delegated key for participating in voting", json_object_new_string("not required"));                 

            dap_list_free_full(l_voting_params->answers_list, NULL);
            DAP_DELETE(l_voting_params->voting_question);
            DAP_DELETE(l_voting_params);
        } break;
        case TX_ITEM_TYPE_VOTE:{
            dap_chain_tx_vote_t *l_vote_item = (dap_chain_tx_vote_t *)item;
            const char *l_hash_str = dap_chain_hash_fast_to_str_static(&l_vote_item->voting_hash);
            json_object_object_add(json_obj_item,"item type", json_object_new_string("VOTE"));
            json_object_object_add(json_obj_item,"Voting hash", json_object_new_string(l_hash_str));
            json_object_object_add(json_obj_item,"Vote answer idx", json_object_new_uint64(l_vote_item->answer_idx));

        } break;
        default:
            json_object_object_add(json_obj_item,"item type", json_object_new_string("This transaction have unknown item type"));
            break;
        }
        json_object_array_add(json_arr_items, json_obj_item);
    }
    json_object_object_add(json_obj_out, "ITEMS", json_arr_items);
    return true;
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
void dap_chain_datum_dump_json(json_object* a_json_arr_reply, json_object  *a_obj_out, dap_chain_datum_t *a_datum, const char *a_hash_out_type, dap_chain_net_id_t a_net_id)
{
    if( a_datum == NULL){
        dap_json_rpc_error_add(a_json_arr_reply, -1,"==Datum is NULL");
        return;
    }
    json_object * json_obj_datum = json_object_new_object();
    dap_hash_fast_t l_datum_hash;
    dap_chain_datum_calc_hash(a_datum, &l_datum_hash);
    const char *l_hash_str = dap_strcmp(a_hash_out_type, "hex")
            ? dap_enc_base58_encode_hash_to_str_static(&l_datum_hash)
            : dap_chain_hash_fast_to_str_static(&l_datum_hash);
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
            json_object_object_add(json_obj_datum,"=== Datum Token Declaration ===",json_object_new_string(""));
            json_object_object_add(json_obj_datum,"hash",json_object_new_string(l_hash_str));
            json_object_object_add(json_obj_datum,"ticker",json_object_new_string(l_token->ticker));
            json_object_object_add(json_obj_datum,"size",json_object_new_uint64(l_token_size));
            json_object_object_add(json_obj_datum,"version",json_object_new_int(l_token->version));
            
            switch (l_token->type) {
                case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL: {
                    json_object_object_add(json_obj_datum,"type",json_object_new_string("DECL"));
                    switch (l_token->subtype) {
                        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:{
                            json_object_object_add(json_obj_datum,"subtype",json_object_new_string("PRIVATE"));
                            json_object_object_add(json_obj_datum,"decimals",json_object_new_uint64(l_token->header_private_decl.decimals));
                            json_object_object_add(json_obj_datum,"auth signs valid",json_object_new_uint64(l_token->signs_valid));
                            json_object_object_add(json_obj_datum,"auth signs total",json_object_new_uint64(l_token->signs_total));
                            json_object_object_add(json_obj_datum,"total_supply",json_object_new_string(dap_uint256_to_char(l_token->total_supply, NULL)));

                            dap_chain_datum_token_flags_dump_to_json(json_obj_datum, "flags",l_token->header_private_decl.flags);
                            dap_datum_token_dump_tsd_to_json(json_obj_datum,l_token, l_token_size, a_hash_out_type);               
                            size_t l_certs_field_size = l_token_size - sizeof(*l_token) - l_token->header_private_update.tsd_total_size;
                            dap_chain_datum_token_certs_dump_to_json(json_obj_datum,l_token->tsd_n_signs + l_token->header_private_update.tsd_total_size,
                                                             l_certs_field_size, a_hash_out_type);                            
                        } break;
                        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE: {
                            json_object_object_add(json_obj_datum,"subtype",json_object_new_string("CF20"));
                            json_object_object_add(json_obj_datum,"decimals",json_object_new_uint64(l_token->header_native_decl.decimals));
                            json_object_object_add(json_obj_datum,"auth signs valid",json_object_new_uint64(l_token->signs_valid));
                            json_object_object_add(json_obj_datum,"auth signs total",json_object_new_uint64(l_token->signs_total));
                            json_object_object_add(json_obj_datum,"total_supply",json_object_new_string(dap_uint256_to_char(l_token->total_supply, NULL)));
                            dap_chain_datum_token_flags_dump_to_json(json_obj_datum, "flags", l_token->header_native_decl.flags);
                            dap_datum_token_dump_tsd_to_json(json_obj_datum, l_token, l_token_size, a_hash_out_type);
                            size_t l_certs_field_size = l_token_size - sizeof(*l_token) - l_token->header_native_decl.tsd_total_size;
                            dap_chain_datum_token_certs_dump_to_json(json_obj_datum, l_token->tsd_n_signs + l_token->header_native_decl.tsd_total_size,
                                                             l_certs_field_size, a_hash_out_type);
                        } break;
                        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC: {
                            dap_chain_addr_t l_premine_addr = l_token->header_public.premine_address;
                            json_object_object_add(json_obj_datum,"subtype",json_object_new_string("PUBLIC"));
                            json_object_object_add(json_obj_datum,"premine_supply", json_object_new_string(dap_uint256_to_char(l_token->header_public.premine_supply, NULL)));
                            json_object_object_add(json_obj_datum,"premine_address", json_object_new_string(dap_chain_addr_to_str_static(&l_premine_addr)));

                            dap_chain_datum_token_flags_dump_to_json(json_obj_datum, "flags", l_token->header_public.flags);
                        } break;
                    }
                } break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE: {
                    json_object_object_add(json_obj_datum,"type",json_object_new_string("UPDATE"));
                    switch (l_token->subtype) {
                        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE: {
                            json_object_object_add(json_obj_datum,"subtype",json_object_new_string("PRIVATE"));
                            json_object_object_add(json_obj_datum,"decimals",json_object_new_uint64(l_token->header_private_decl.decimals));
                            json_object_object_add(json_obj_datum,"auth signs valid",json_object_new_uint64(l_token->signs_valid));
                            json_object_object_add(json_obj_datum,"auth signs total",json_object_new_uint64(l_token->signs_total));
                            json_object_object_add(json_obj_datum,"total_supply",json_object_new_string(dap_uint256_to_char(l_token->total_supply, NULL)));
                            
                            dap_datum_token_dump_tsd_to_json(json_obj_datum, l_token, l_token_size, a_hash_out_type);
                            size_t l_certs_field_size = l_token_size - sizeof(*l_token) - l_token->header_private_update.tsd_total_size;
                            dap_chain_datum_token_certs_dump_to_json(json_obj_datum, l_token->tsd_n_signs + l_token->header_private_update.tsd_total_size,
                                                             l_certs_field_size, a_hash_out_type);
                        } break;
                        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE: {
                            json_object_object_add(json_obj_datum,"subtype", json_object_new_string("CF20"));
                            json_object_object_add(json_obj_datum,"decimals", json_object_new_uint64(l_token->header_native_update.decimals));
                            json_object_object_add(json_obj_datum,"auth signs valid",json_object_new_uint64(l_token->signs_valid));
                            json_object_object_add(json_obj_datum,"auth signs total",json_object_new_uint64(l_token->signs_total));
                            json_object_object_add(json_obj_datum,"total_supply",json_object_new_string(dap_uint256_to_char(l_token->total_supply, NULL)));
                            
                            dap_datum_token_dump_tsd_to_json(json_obj_datum, l_token, l_token_size, a_hash_out_type);
                            size_t l_certs_field_size = l_token_size - sizeof(*l_token) - l_token->header_native_update.tsd_total_size;
                            dap_chain_datum_token_certs_dump_to_json(json_obj_datum, l_token->tsd_n_signs + l_token->header_native_update.tsd_total_size,
                                                             l_certs_field_size, a_hash_out_type);
                        } break;
                    }
                } break;
                default:
                    json_object_object_add(json_obj_datum,"type", json_object_new_string("UNKNOWN"));
                    break;
            }
            if (l_token->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE ) {
                json_object_object_add(json_obj_datum,"subtype", json_object_new_string("SIMPLE"));
                json_object_object_add(json_obj_datum,"decimals", json_object_new_uint64(l_token->header_simple.decimals));
                json_object_object_add(json_obj_datum,"sign_total", json_object_new_uint64(l_token->signs_total));
                json_object_object_add(json_obj_datum,"sign_valid", json_object_new_uint64(l_token->signs_valid));
                json_object_object_add(json_obj_datum,"total_supply",json_object_new_string(dap_uint256_to_char(l_token->total_supply, NULL)));
                
                size_t l_certs_field_size = l_token_size - sizeof(*l_token);
                dap_chain_datum_token_certs_dump_to_json(json_obj_datum, l_token->tsd_n_signs,
                                                 l_certs_field_size, a_hash_out_type);
            }
            DAP_DELETE(l_token);
        } break;
        case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
            size_t l_emission_size = a_datum->header.data_size;
            dap_chain_datum_token_emission_t *l_emission = dap_chain_datum_emission_read(a_datum->data, &l_emission_size);
            const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_emission->hdr.value, &l_coins_str);
            json_object_object_add(json_obj_datum,"emission hash", json_object_new_string(l_hash_str));
            json_object_object_add(json_obj_datum,"coins", json_object_new_string(l_coins_str));
            json_object_object_add(json_obj_datum,"value", json_object_new_string(l_value_str));
            json_object_object_add(json_obj_datum,"ticker", json_object_new_string(l_emission->hdr.ticker));
            json_object_object_add(json_obj_datum,"type", json_object_new_string(dap_chain_datum_emission_type_str(l_emission->hdr.type)));
            json_object_object_add(json_obj_datum,"version", json_object_new_uint64(l_emission->hdr.version));
            json_object_object_add(json_obj_datum,"to addr", json_object_new_string(dap_chain_addr_to_str_static(&(l_emission->hdr.address))));

            switch (l_emission->hdr.type) {
            case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH:
                json_object_object_add(json_obj_datum,"signs_count", json_object_new_uint64(l_emission->data.type_auth.signs_count));
                json_object_object_add(json_obj_datum,"tsd_total_size", json_object_new_uint64(l_emission->data.type_auth.tsd_total_size));

                if (  ( (void *) l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size) >
                      ((void *) l_emission + l_emission_size) )
                {
                    log_it(L_ERROR, "Illformed DATUM type %d, TSD section is out-of-buffer (%" DAP_UINT64_FORMAT_U " vs %zu)",
                        l_emission->hdr.type, l_emission->data.type_auth.tsd_total_size, l_emission_size);
                    dap_json_rpc_error_add(a_json_arr_reply, -3,"Skip incorrect or illformed DATUM");
                    break;
                }
                dap_chain_datum_token_certs_dump_to_json(json_obj_datum, l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size,
                                                l_emission->data.type_auth.tsd_n_signs_size - l_emission->data.type_auth.tsd_total_size, a_hash_out_type);
                break;
            case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ALGO:
                json_object_object_add(json_obj_datum,"codename",json_object_new_string(l_emission->data.type_algo.codename));
                break;
            case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_SMART_CONTRACT: {
                char l_time_str[32];
                char l_flags[50] = {};
                // get time of create datum
                if(dap_time_to_str_rfc822(l_time_str, sizeof(l_time_str), l_emission->data.type_presale.lock_time) < 1)
                        l_time_str[0] = '\0';                        
                snprintf(l_flags, 50, "0x%x", l_emission->data.type_presale.flags);
                json_object_object_add(json_obj_datum,"flags", json_object_new_string(l_flags));
                json_object_object_add(json_obj_datum,"lock_time", json_object_new_string(l_time_str));
                json_object_object_add(json_obj_datum,"addr", json_object_new_string(dap_chain_addr_to_str_static(&l_emission->data.type_presale.addr)));                
            }
            case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ATOM_OWNER:
            case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_UNDEFINED:
            default:
                break;
            }
            DAP_DELETE(l_emission);
        } break;
        case DAP_CHAIN_DATUM_TX: {
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*)a_datum->data;
            dap_chain_datum_dump_tx_json(a_json_arr_reply, l_tx, NULL, json_obj_datum, a_hash_out_type, &l_datum_hash, a_net_id);
        } break;
        case DAP_CHAIN_DATUM_DECREE:{
            dap_chain_datum_decree_t *l_decree = (dap_chain_datum_decree_t *)a_datum->data;
            size_t l_decree_size = dap_chain_datum_decree_get_size(l_decree);
            json_object_object_add(json_obj_datum,"=== Datum decree ===",json_object_new_string("empty"));
            json_object_object_add(json_obj_datum,"hash",json_object_new_string(l_hash_str));
            json_object_object_add(json_obj_datum,"size",json_object_new_uint64(l_decree_size));
            dap_chain_datum_decree_dump_json(json_obj_datum, l_decree, l_decree_size, a_hash_out_type);
        } break;
        case DAP_CHAIN_DATUM_ANCHOR:{
            dap_chain_datum_anchor_t *l_anchor = (dap_chain_datum_anchor_t *)a_datum->data;
            size_t l_anchor_size = sizeof(dap_chain_datum_anchor_t) + l_anchor->header.data_size + l_anchor->header.signs_size;
            json_object_object_add(json_obj_datum,"=== Datum anchor ===",json_object_new_string("empty"));
            json_object_object_add(json_obj_datum,"hash",json_object_new_string(l_hash_str));
            json_object_object_add(json_obj_datum,"size",json_object_new_uint64(l_anchor_size));
            dap_hash_fast_t l_decree_hash = { };
            dap_chain_datum_anchor_get_hash_from_data(l_anchor, &l_decree_hash);
            l_hash_str = dap_chain_hash_fast_to_str_static(&l_decree_hash);
            json_object_object_add(json_obj_datum,"decree hash",json_object_new_string(l_hash_str));
            dap_chain_datum_anchor_certs_dump_json(json_obj_datum,l_anchor->data_n_sign + l_anchor->header.data_size, l_anchor->header.signs_size, a_hash_out_type);
        } break;
    }  
    json_object_object_add(a_obj_out,"Datum",json_obj_datum);  
}
