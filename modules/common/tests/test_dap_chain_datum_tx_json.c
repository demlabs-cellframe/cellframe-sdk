/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network https://cellframe.net
 * Copyright  (c) 2022
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

#include "dap_chain_datum_tx_json_tests.h"
#include "dap_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_receipt.h"
#include "dap_chain_datum_tx_pkey.h"
#include "dap_chain_datum_tx_voting.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_chain_datum_tx_in_ems.h"
#include "dap_chain_datum_tx_in_reward.h"
#include "dap_chain_datum_tx_in_cond.h"
#include "dap_chain_datum_tx_out.h"
#include "dap_chain_datum_tx_event.h"
#include "dap_chain_common.h"
#include "dap_chain_net.h"
#include "dap_chain_net_tx.h"
#include "dap_enc_key.h"
#include "dap_sign.h"
#include "dap_time.h"
#include "dap_pkey.h"
#include "dap_chain_net_srv.h"
#include "json.h"

#define LOG_TAG "test_dap_chain_datum_tx_json"

// Forward declarations for old functions
/**
* @brief dap_chain_datum_dump_tx_json_old
*
* @param a_datum
* @param a_ledger
* @param a_str_out
* @param a_hash_out_type
* @param save_processed_tx
* @param a_tx_hash_processed
* @param l_tx_num
*/
bool dap_chain_datum_dump_tx_json_old(json_object* a_json_arr_reply,
                                            dap_chain_datum_tx_t *a_datum,
                                            const char *a_ticker,
                                            json_object* json_obj_out,
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
   json_object* json_arr_items = json_object_new_array();
   dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, a_datum->header.ts_created);
   l_is_first ? 
   json_object_object_add(json_obj_out, a_version == 1 ? "first transaction" : "first_transaction", json_object_new_string("emit")):
   json_object_object_add(json_obj_out, a_version == 1 ?  "first transaction" : "first_transaction", json_object_new_string(a_version == 1 ? "" : "empty"));
   json_object_object_add(json_obj_out, "hash", json_object_new_string(l_hash_str));
   json_object_object_add(json_obj_out, a_version == 1 ?  "tx created" : "tx_created", json_object_new_string(l_tmp_buf));
   json_object_object_add(json_obj_out, a_version == 1 ?  "token ticker" : "token_ticker", a_ticker ? json_object_new_string(a_ticker) : json_object_new_string(a_version == 1 ? "" : "empty"));
   //json_object_array_add(json_arr_items, json_obj_tx);
   dap_hash_fast_t l_hash_tmp = { };
   byte_t *item; size_t l_size;
   TX_ITEM_ITER_TX(item, l_size, a_datum) {
       json_object* json_obj_item = json_object_new_object();
       if (a_version != 1)
           json_object_object_add(json_obj_item, "item_type", json_object_new_string(dap_chain_datum_tx_item_type_to_str_short(*item)));
       switch (*item) {
       case TX_ITEM_TYPE_IN:
           l_hash_tmp = ((dap_chain_tx_in_t*)item)->header.tx_prev_hash;
           l_hash_str = !dap_hash_fast_is_blank(&l_hash_tmp)
               ? dap_strcmp(a_hash_out_type, "hex") ? dap_enc_base58_encode_hash_to_str_static(&l_hash_tmp) : dap_chain_hash_fast_to_str_static(&l_hash_tmp)
               : "BLANK";
           if (a_version == 1)
               json_object_object_add(json_obj_item, "item type", json_object_new_string("IN"));
           json_object_object_add(json_obj_item, a_version == 1 ? "Tx prev hash" : "tx_prev_hash", json_object_new_string(l_hash_str));
           json_object_object_add(json_obj_item, a_version == 1 ? "Tx out prev idx" : "tx_out_prev_idx", json_object_new_uint64(((dap_chain_tx_in_t*)item)->header.tx_out_prev_idx));
           break;
       case TX_ITEM_TYPE_OUT_OLD: {
           const char *l_value_str = dap_uint256_to_char(
               dap_chain_uint256_from(((dap_chain_tx_out_old_t*)item)->header.value), NULL );
           if (a_version == 1)
               json_object_object_add(json_obj_item, "item type", json_object_new_string("OUT OLD"));
           json_object_object_add(json_obj_item, a_version == 1 ? "Value" : "value", json_object_new_string(l_value_str));
           json_object_object_add(json_obj_item, a_version == 1 ? "Address" : "addr", json_object_new_string(dap_chain_addr_to_str_static(&((dap_chain_tx_out_old_t*)item)->addr)));
       } break;
       case TX_ITEM_TYPE_OUT: { // 256
           const char *l_coins_str,
                   *l_value_str = dap_uint256_to_char(((dap_chain_tx_out_t*)item)->header.value, &l_coins_str),
                   *l_addr_str = dap_chain_addr_to_str_static(&((dap_chain_tx_out_t*)item)->addr);
           if (a_version == 1)
               json_object_object_add(json_obj_item, "item type", json_object_new_string("OUT"));
           json_object_object_add(json_obj_item, a_version == 1 ? "Coins" : "coins", json_object_new_string(l_coins_str));
           json_object_object_add(json_obj_item, a_version == 1 ? "Value": "value", json_object_new_string(l_value_str));

           json_object_object_add(json_obj_item, a_version == 1 ? "Address" : "addr", json_object_new_string(l_addr_str));            
       } break;
       case TX_ITEM_TYPE_IN_EMS: {
           char l_tmp_buff[70];
           l_hash_tmp = ((dap_chain_tx_in_ems_t*)item)->header.token_emission_hash;
           l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                   ? dap_enc_base58_encode_hash_to_str_static(&l_hash_tmp)
                   : dap_chain_hash_fast_to_str_static(&l_hash_tmp);
           if (a_version == 1)
               json_object_object_add(json_obj_item, "item type", json_object_new_string("IN_EMS"));
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
           if (a_version == 1)
               json_object_object_add(json_obj_item, "item type", json_object_new_string("IN_REWARD"));
           json_object_object_add(json_obj_item,"block_hash", json_object_new_string(l_hash_str));
       } break;
       case TX_ITEM_TYPE_SIG: {
           dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t*)item);
           if (a_version == 1)
               json_object_object_add(json_obj_item, "item type", json_object_new_string("SIG"));
           dap_sign_get_information_json(a_json_arr_reply, l_sign, json_obj_item, a_hash_out_type, a_version);
           dap_chain_addr_t l_sender_addr;
           dap_chain_addr_fill_from_sign(&l_sender_addr, l_sign, a_net_id);
           json_object_object_add(json_obj_item, a_version == 1 ? "Sender addr" : "sender_addr", json_object_new_string(dap_chain_addr_to_str_static(&l_sender_addr)));            
       } break;
       case TX_ITEM_TYPE_RECEIPT_OLD:{
           dap_chain_datum_tx_receipt_old_t *l_receipt_old = (dap_chain_datum_tx_receipt_old_t*)item;
           const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_receipt_old->receipt_info.value_datoshi, &l_coins_str);
           json_object_object_add(json_obj_item,"item type", json_object_new_string("RECEIPT"));
           json_object_object_add(json_obj_item,"size", json_object_new_uint64(l_receipt_old->size));
           json_object_object_add(json_obj_item,"ext size", json_object_new_uint64(l_receipt_old->exts_size));
           json_object_object_add(json_obj_item,"INFO", json_object_new_string(""));
           json_object_object_add(json_obj_item,"units", json_object_new_uint64(l_receipt_old->receipt_info.units));
           json_object_object_add(json_obj_item,"uid", json_object_new_uint64(l_receipt_old->receipt_info.srv_uid.uint64));
           json_object_object_add(json_obj_item,"units type", json_object_new_string(dap_chain_srv_unit_enum_to_str(l_receipt_old->receipt_info.units_type.enm)));
           json_object_object_add(json_obj_item,"coins", json_object_new_string(l_coins_str));
           json_object_object_add(json_obj_item,"value", json_object_new_string(l_value_str));
           json_object_object_add(json_obj_item,"Exts",json_object_new_string(""));                         
           switch (l_receipt_old->exts_size) {
           case (sizeof(dap_sign_t) * 2): {
               dap_sign_t *l_client = (dap_sign_t*)(l_receipt_old->exts_n_signs  + sizeof(dap_sign_t));
               json_object_object_add(json_obj_item,"Client", json_object_new_string(""));
               dap_sign_get_information_json(a_json_arr_reply, l_client, json_obj_item, a_hash_out_type, a_version);                
           }
           case (sizeof(dap_sign_t)): {
               dap_sign_t *l_provider = (dap_sign_t*)(l_receipt_old->exts_n_signs);
               json_object_object_add(json_obj_item,"Provider", json_object_new_string(""));
               dap_sign_get_information_json(a_json_arr_reply, l_provider,json_obj_item, a_hash_out_type, a_version);
               break;
           }
           }
       } break;
       case TX_ITEM_TYPE_RECEIPT: {
           const char *l_coins_str, *l_value_str = dap_uint256_to_char(((dap_chain_datum_tx_receipt_t*)item)->receipt_info.value_datoshi, &l_coins_str);
           if (a_version == 1)
               json_object_object_add(json_obj_item, "item type", json_object_new_string("RECEIPT"));
           json_object_object_add(json_obj_item, "size", json_object_new_uint64(((dap_chain_datum_tx_receipt_t*)item)->size));
           json_object_object_add(json_obj_item, a_version == 1 ? "ext size" : "ext_size", json_object_new_uint64(((dap_chain_datum_tx_receipt_t*)item)->exts_size));
           json_object_object_add(json_obj_item, a_version == 1 ? "INFO" : "info", json_object_new_string(""));

           json_object_object_add(json_obj_item,"units", json_object_new_uint64(((dap_chain_datum_tx_receipt_t*)item)->receipt_info.units));
           json_object_object_add(json_obj_item,"uid", json_object_new_uint64(((dap_chain_datum_tx_receipt_t*)item)->receipt_info.srv_uid.uint64));
           json_object_object_add(json_obj_item, a_version == 1 ? "units type" : "units_type", json_object_new_string(dap_chain_srv_unit_enum_to_str(((dap_chain_datum_tx_receipt_t*)item)->receipt_info.units_type.enm)));
           json_object_object_add(json_obj_item, "coins", json_object_new_string(l_coins_str));
           json_object_object_add(json_obj_item,"value", json_object_new_string(l_value_str));
           if (a_version == 1)
               json_object_object_add(json_obj_item, "Exts",json_object_new_string(""));                         
           switch ( ((dap_chain_datum_tx_receipt_t*)item)->exts_size ) {
           case (sizeof(dap_sign_t) * 2): {
               dap_sign_t *l_client = (dap_sign_t*)( ((dap_chain_datum_tx_receipt_t*)item)->exts_n_signs + sizeof(dap_sign_t) );
               json_object_object_add(json_obj_item, a_version == 1 ? "Client" : "sig_inf", json_object_new_string(a_version == 1 ? "" : "client"));
               dap_sign_get_information_json(a_json_arr_reply, l_client, json_obj_item, a_hash_out_type, a_version);                
           }
           case (sizeof(dap_sign_t)): {
               dap_sign_t *l_provider = (dap_sign_t*)( ((dap_chain_datum_tx_receipt_t*)item)->exts_n_signs );
               json_object_object_add(json_obj_item, a_version == 1 ? "Provider" : "sig_inf", json_object_new_string(a_version == 1 ? "" : "provider"));
               dap_sign_get_information_json(a_json_arr_reply, l_provider,json_obj_item, a_hash_out_type, a_version);
               break;
           }
           }
       } break;
       case TX_ITEM_TYPE_PKEY: {
            dap_pkey_t *l_pkey = (dap_pkey_t *)(item + sizeof(dap_chain_tx_item_type_t));
            dap_chain_hash_fast_t l_pkey_hash;
            dap_hash_fast(l_pkey->pkey, l_pkey->header.size, &l_pkey_hash);
            const char *l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str_static(&l_pkey_hash)
                    : dap_chain_hash_fast_to_str_static(&l_pkey_hash);
            if (a_version == 1)
                json_object_object_add(json_obj_item, "item type", json_object_new_string("PKey"));
            json_object_object_add(json_obj_item, "pkey", json_object_new_string(""));
            json_object_object_add(json_obj_item, "pkey_type", json_object_new_string(dap_pkey_type_to_str(((dap_chain_tx_pkey_t*)item)->header.type)));
            json_object_object_add(json_obj_item, "pkey_size", json_object_new_uint64(((dap_chain_tx_pkey_t*)item)->header.size));
            json_object_object_add(json_obj_item, "key", json_object_new_string(""));
            json_object_object_add(json_obj_item, "type", json_object_new_string(dap_pkey_type_to_str(l_pkey->header.type)));
            json_object_object_add(json_obj_item, "size", json_object_new_uint64(l_pkey->header.size));
            json_object_object_add(json_obj_item, "hash", json_object_new_string(l_hash_str));
        } break;
       case TX_ITEM_TYPE_TSD: {
           if (a_version == 1)
               json_object_object_add(json_obj_item, "item type", json_object_new_string("TSD data"));
           json_object_object_add(json_obj_item, a_version == 1 ? "type" : "data_type", json_object_new_uint64(((dap_chain_tx_tsd_t*)item)->header.type));
           json_object_object_add(json_obj_item,"size", json_object_new_uint64(((dap_chain_tx_tsd_t*)item)->header.size));            
       } break;
       case TX_ITEM_TYPE_IN_COND:
           if (a_version == 1)
               json_object_object_add(json_obj_item, "item type", json_object_new_string("IN COND"));
           l_hash_tmp = ((dap_chain_tx_in_cond_t*)item)->header.tx_prev_hash;
           l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                   ? dap_enc_base58_encode_hash_to_str_static(&l_hash_tmp)
                   : dap_chain_hash_fast_to_str_static(&l_hash_tmp);
           json_object_object_add(json_obj_item, a_version == 1 ? "Receipt_idx" : "receipt_idx", json_object_new_int(((dap_chain_tx_in_cond_t*)item)->header.receipt_idx));
           json_object_object_add(json_obj_item, a_version == 1 ? "Tx_prev_hash" : "tx_prev_hash", json_object_new_string(l_hash_str));
           json_object_object_add(json_obj_item, a_version == 1 ? "Tx_out_prev_idx" : "tx_out_prev_idx", json_object_new_uint64(((dap_chain_tx_in_cond_t*)item)->header.tx_out_prev_idx));
           break;
       case TX_ITEM_TYPE_OUT_COND: {
           char l_tmp_buff[70];
           if (a_version == 1)
               json_object_object_add(json_obj_item, "item type", json_object_new_string("OUT COND"));
           const char *l_coins_str, *l_value_str = dap_uint256_to_char(((dap_chain_tx_out_cond_t*)item)->header.value, &l_coins_str);
           dap_time_t l_ts_exp = ((dap_chain_tx_out_cond_t*)item)->header.ts_expires;
           dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_ts_exp);
           json_object_object_add(json_obj_item,"ts_expires", l_ts_exp ? json_object_new_string(l_tmp_buf) : json_object_new_string("never"));
           json_object_object_add(json_obj_item,"coins", json_object_new_string(l_coins_str));
           json_object_object_add(json_obj_item,"value", json_object_new_string(l_value_str));
           json_object_object_add(json_obj_item,"subtype", json_object_new_string(dap_chain_tx_out_cond_subtype_to_str(((dap_chain_tx_out_cond_t*)item)->header.subtype)));
           snprintf(l_tmp_buff, sizeof(l_tmp_buff), "0x%016"DAP_UINT64_FORMAT_x"",((dap_chain_tx_out_cond_t*)item)->header.srv_uid.uint64);
           json_object_object_add(json_obj_item,"uid", json_object_new_string(l_tmp_buff));

           json_object_object_add(json_obj_item, "tsd_size", json_object_new_uint64(((dap_chain_tx_out_cond_t *)item)->tsd_size));
           switch (((dap_chain_tx_out_cond_t*)item)->header.subtype) {
               case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY: {
                   const char *l_coins_str, *l_value_str =
                       dap_uint256_to_char( ((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.unit_price_max_datoshi, &l_coins_str );
                   l_hash_tmp = ((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.pkey_hash;
                   l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                           ? dap_enc_base58_encode_hash_to_str_static(&l_hash_tmp)
                           : dap_chain_hash_fast_to_str_static(&l_hash_tmp);
                   snprintf(l_tmp_buff, sizeof(l_tmp_buff), "0x%08x",((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.unit.uint32);
                   json_object_object_add(json_obj_item, "unit", json_object_new_string(l_tmp_buff));
                   json_object_object_add(json_obj_item, "pkey", json_object_new_string(l_hash_str));
                   json_object_object_add(json_obj_item, a_version == 1 ? "max price(coins)" : "max_price_coins", json_object_new_string(l_coins_str));
                   json_object_object_add(json_obj_item, a_version == 1 ? "max price(value)" : "max_price_value", json_object_new_string(l_value_str));
               } break;
               case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE: {
                   dap_chain_node_addr_t *l_signer_node_addr = &((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake_pos_delegate.signer_node_addr;
                   dap_chain_addr_t *l_signing_addr = &((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake_pos_delegate.signing_addr;
                   l_hash_tmp = l_signing_addr->data.hash_fast;
                   l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                           ? dap_enc_base58_encode_hash_to_str_static(&l_hash_tmp)
                           : dap_chain_hash_fast_to_str_static(&l_hash_tmp);
                   json_object_object_add(json_obj_item, a_version == 1 ? "signing_addr" : "sig_addr", json_object_new_string(dap_chain_addr_to_str_static(l_signing_addr)));
                   json_object_object_add(json_obj_item, a_version == 1 ? "with pkey hash" : "sig_pkey_hash", json_object_new_string(l_hash_str));                    
                   snprintf(l_tmp_buff, sizeof(l_tmp_buff), ""NODE_ADDR_FP_STR"",NODE_ADDR_FP_ARGS(l_signer_node_addr));
                   json_object_object_add(json_obj_item, a_version == 1 ? "signer_node_addr" : "sig_node_addr", json_object_new_string(l_tmp_buff));
                   
               } break;
               case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE: {
                   const char *l_rate_str;
                   dap_uint256_to_char( (((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.rate), &l_rate_str );
                   snprintf(l_tmp_buff,sizeof(l_tmp_buff),"0x%016"DAP_UINT64_FORMAT_x"",((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.buy_net_id.uint64);
                   json_object_object_add(json_obj_item, a_version == 1 ? "net id" : "net_id", json_object_new_string(l_tmp_buff));
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
           if (a_version == 1)
               json_object_object_add(json_obj_item, "item type", json_object_new_string("OUT EXT"));
           json_object_object_add(json_obj_item,"addr", json_object_new_string(dap_chain_addr_to_str_static(&((dap_chain_tx_out_ext_t*)item)->addr)));
           json_object_object_add(json_obj_item,"token", json_object_new_string(((dap_chain_tx_out_ext_t*)item)->token));
           json_object_object_add(json_obj_item,"coins", json_object_new_string(l_coins_str));
           json_object_object_add(json_obj_item,"value", json_object_new_string(l_value_str));
       } break;
       case TX_ITEM_TYPE_OUT_STD: {
           const char *l_coins_str, *l_value_str = dap_uint256_to_char( ((dap_chain_tx_out_std_t *)item)->value, &l_coins_str );
           if (a_version == 1)
               json_object_object_add(json_obj_item, "item type", json_object_new_string("OUT STD"));
           json_object_object_add(json_obj_item, "addr", json_object_new_string(dap_chain_addr_to_str_static(&((dap_chain_tx_out_std_t *)item)->addr)));
           json_object_object_add(json_obj_item, "token", json_object_new_string(((dap_chain_tx_out_std_t *)item)->token));
           json_object_object_add(json_obj_item, "coins", json_object_new_string(l_coins_str));
           json_object_object_add(json_obj_item, "value", json_object_new_string(l_value_str));
           dap_time_t l_ts_unlock = ((dap_chain_tx_out_std_t *)item)->ts_unlock;
           dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_ts_unlock);
           json_object_object_add(json_obj_item, "time_unlock", json_object_new_string(l_ts_unlock ? l_tmp_buf : "not_locked"));
       } break;
       case TX_ITEM_TYPE_VOTING:{
           size_t l_tsd_size = 0;

           dap_chain_tx_tsd_t *l_item = (dap_chain_tx_tsd_t *)dap_chain_datum_tx_item_get(a_datum, NULL, (byte_t*)item + l_size, TX_ITEM_TYPE_TSD, &l_tsd_size);
           if (!l_item || !l_tsd_size)
                   break;
           dap_chain_datum_tx_voting_params_t *l_voting_params = dap_chain_voting_parse_tsd(a_datum);
           if (a_version == 1)
               json_object_object_add(json_obj_item, "item type", json_object_new_string("VOTING"));
           json_object_object_add(json_obj_item, a_version == 1 ? "Voting question" : "voting_question", json_object_new_string(l_voting_params->voting_question));
           json_object_object_add(json_obj_item, a_version == 1 ? "Answer options" : "answer_options", json_object_new_string(""));
           
           dap_list_t *l_temp = l_voting_params->answers_list;
           uint8_t l_index = 0;
           while (l_temp) {
               json_object_object_add(json_obj_item, dap_itoa(l_index), json_object_new_string((char *)l_temp->data));
               l_index++;
               l_temp = l_temp->next;
           }
           if (l_voting_params->voting_expire) {
               dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_voting_params->voting_expire);
               json_object_object_add(json_obj_item, a_version == 1 ? "Voting expire" : "voting_expire", json_object_new_string(l_tmp_buf));                
           }
           if (l_voting_params->votes_max_count) {
               json_object_object_add(json_obj_item, a_version == 1 ? "Votes max count" : "votes_max_count", json_object_new_uint64(l_voting_params->votes_max_count));
           }
           if (a_version == 1) {
               json_object_object_add(json_obj_item,"Changing vote is", l_voting_params->vote_changing_allowed ? json_object_new_string("available") : 
                                   json_object_new_string("not available"));
               l_voting_params->delegate_key_required ?
                   json_object_object_add(json_obj_item, "Delegated key for participating in voting", json_object_new_string("required")) :
                   json_object_object_add(json_obj_item, "Delegated key for participating in voting", json_object_new_string("not required"));  
           } else {
               json_object_object_add(json_obj_item,"changing_vote", json_object_new_boolean(l_voting_params->vote_changing_allowed));
               json_object_object_add(json_obj_item,"delegate_key_required", json_object_new_boolean(l_voting_params->delegate_key_required));   
           }
           dap_list_free_full(l_voting_params->answers_list, NULL);
           DAP_DELETE(l_voting_params->voting_question);
           DAP_DELETE(l_voting_params);
       } break;
       case TX_ITEM_TYPE_VOTE:{
           dap_chain_tx_vote_t *l_vote_item = (dap_chain_tx_vote_t *)item;
           const char *l_hash_str = dap_chain_hash_fast_to_str_static(&l_vote_item->voting_hash);
           if (a_version == 1)
               json_object_object_add(json_obj_item, "item type", json_object_new_string("VOTE"));
           json_object_object_add(json_obj_item, a_version == 1 ? "Voting hash" : "voting_hash", json_object_new_string(l_hash_str));
           json_object_object_add(json_obj_item, a_version == 1 ? "Vote answer idx" : "vote_answer_idx", json_object_new_uint64(l_vote_item->answer_idx));
       } break;
       default:
           if (a_version == 1)
               json_object_object_add(json_obj_item, "item type", json_object_new_string("This transaction have unknown item type"));
           break;
       }
       json_object_array_add(json_arr_items, json_obj_item);
   }
   json_object_object_add(json_obj_out, a_version == 1 ? "ITEMS" : "items", json_arr_items);
   return true;
}



/**
 * @brief Create a comprehensive test transaction with all item types
 * @return Pointer to created transaction datum
 */
static dap_chain_datum_tx_t *create_test_transaction(void)
{
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create test transaction");
        return NULL;
    }
    
    l_tx->header.ts_created = dap_time_now();
    
    // Add an IN item
    dap_chain_hash_fast_t l_prev_hash = {};
    dap_chain_tx_in_t *l_in_item = dap_chain_datum_tx_item_in_create(&l_prev_hash, 0);
    if (l_in_item) {
        l_in_item->header.type = TX_ITEM_TYPE_IN;
        dap_chain_datum_tx_add_item(&l_tx, l_in_item);
        DAP_DELETE(l_in_item);
    }
    
    // Add an OUT_OLD item
    dap_chain_addr_t l_addr_old = {};
    uint64_t l_value_old = 500;
    dap_chain_tx_out_old_t *l_out_old_item = DAP_NEW_Z(dap_chain_tx_out_old_t);
    if (l_out_old_item) {
        l_out_old_item->header.type = TX_ITEM_TYPE_OUT_OLD;
        l_out_old_item->header.value = l_value_old;
        l_out_old_item->addr = l_addr_old;
        dap_chain_datum_tx_add_item(&l_tx, l_out_old_item);
        DAP_DELETE(l_out_old_item);
    }
    
    // Add an OUT item
    dap_chain_addr_t l_addr = {};
    uint256_t l_value = dap_chain_uint256_from(1000);
    dap_chain_tx_out_t *l_out_item = dap_chain_datum_tx_item_out_create(&l_addr, l_value);
    if (l_out_item) {
        l_out_item->header.type = TX_ITEM_TYPE_OUT;
        dap_chain_datum_tx_add_item(&l_tx, l_out_item);
        DAP_DELETE(l_out_item);
    }
    
    // Add an IN_EMS item
    dap_chain_id_t l_chain_id = {.uint64 = 1};
    dap_chain_hash_fast_t l_token_hash = {};
    dap_chain_tx_in_ems_t *l_in_ems_item = dap_chain_datum_tx_item_in_ems_create(l_chain_id, &l_token_hash, "TEST");
    if (l_in_ems_item) {
        l_in_ems_item->header.type = TX_ITEM_TYPE_IN_EMS;
        dap_chain_datum_tx_add_item(&l_tx, l_in_ems_item);
        DAP_DELETE(l_in_ems_item);
    }
    
    // Add an IN_REWARD item
    dap_chain_hash_fast_t l_block_hash = {};
    dap_chain_tx_in_reward_t *l_in_reward_item = dap_chain_datum_tx_item_in_reward_create(&l_block_hash);
    if (l_in_reward_item) {
        l_in_reward_item->type = TX_ITEM_TYPE_IN_REWARD;
        dap_chain_datum_tx_add_item(&l_tx, l_in_reward_item);
        DAP_DELETE(l_in_reward_item);
    }
    
    // Add an IN_COND item
    dap_chain_tx_in_cond_t *l_in_cond_item = dap_chain_datum_tx_item_in_cond_create(&l_prev_hash, 0, 0);
    if (l_in_cond_item) {
        l_in_cond_item->header.type = TX_ITEM_TYPE_IN_COND;
        dap_chain_datum_tx_add_item(&l_tx, l_in_cond_item);
        DAP_DELETE(l_in_cond_item);
    }
    
    // OUT_COND: srv_uid присваивается явно
    dap_chain_net_srv_uid_t l_srv_uid;
    // Определения констант для теста
    #ifndef DAP_CHAIN_NET_SRV_PAY_ID
    #define DAP_CHAIN_NET_SRV_PAY_ID 1
    #endif
    #ifndef DAP_CHAIN_NET_SRV_XCHANGE_ID
    #define DAP_CHAIN_NET_SRV_XCHANGE_ID 2
    #endif
    #ifndef DAP_CHAIN_NET_SRV_STAKE_POS_ID
    #define DAP_CHAIN_NET_SRV_STAKE_POS_ID 3
    #endif
    #ifndef DAP_CHAIN_NET_SRV_STAKE_LOCK_ID
    #define DAP_CHAIN_NET_SRV_STAKE_LOCK_ID 4
    #endif
    #ifndef DAP_CHAIN_NET_SRV_WALLET_SHARED_ID
    #define DAP_CHAIN_NET_SRV_WALLET_SHARED_ID 5
    #endif
    // 1. OUT_COND with SRV_PAY subtype
    dap_enc_key_t *l_key = dap_enc_key_new(DAP_ENC_KEY_TYPE_SIG_BLISS);
    if (l_key) {
        dap_pkey_t *l_pkey = dap_pkey_from_enc_key(l_key);
        if (l_pkey) {
            l_srv_uid.uint64 = DAP_CHAIN_NET_SRV_PAY_ID;
            dap_chain_net_srv_price_unit_uid_t l_unit = {.uint32 = 1};
            uint256_t l_value_pay = dap_chain_uint256_from(200);
            uint256_t l_max_price = dap_chain_uint256_from(10);
            dap_chain_tx_out_cond_t *l_out_cond_pay = dap_chain_datum_tx_item_out_cond_create_srv_pay(
                l_pkey, l_srv_uid, l_value_pay, l_max_price, l_unit, NULL, 0);
            if (l_out_cond_pay) {
                l_out_cond_pay->header.item_type = TX_ITEM_TYPE_OUT_COND;
                dap_chain_datum_tx_add_item(&l_tx, l_out_cond_pay);
                DAP_DELETE(l_out_cond_pay);
            }
        }
        dap_enc_key_delete(l_key);
    }
    
    // 2. OUT_COND with SRV_XCHANGE subtype
    dap_chain_net_id_t l_sell_net_id = {.uint64 = 1};
    dap_chain_net_id_t l_buy_net_id = {.uint64 = 2};
    uint256_t l_value_sell = dap_chain_uint256_from(300);
    uint256_t l_rate = dap_chain_uint256_from(100);
    l_srv_uid.uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID;
    dap_chain_tx_out_cond_t *l_out_cond_xchange = dap_chain_datum_tx_item_out_cond_create_srv_xchange(
        l_srv_uid, l_sell_net_id, l_value_sell, l_buy_net_id, "TOKEN", l_rate, &l_addr, NULL, 0);
    if (l_out_cond_xchange) {
        l_out_cond_xchange->header.item_type = TX_ITEM_TYPE_OUT_COND;
        dap_chain_datum_tx_add_item(&l_tx, l_out_cond_xchange);
        DAP_DELETE(l_out_cond_xchange);
    }
    
    // 3. OUT_COND with SRV_STAKE_POS_DELEGATE subtype
    l_srv_uid.uint64 = DAP_CHAIN_NET_SRV_STAKE_POS_ID;
    dap_chain_node_addr_t l_node_addr = {};
    dap_chain_tx_out_cond_t *l_out_cond_delegate = DAP_NEW_Z(dap_chain_tx_out_cond_t);
    if (l_out_cond_delegate) {
        l_out_cond_delegate->header.item_type = TX_ITEM_TYPE_OUT_COND;
        l_out_cond_delegate->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE;
        l_out_cond_delegate->header.value = dap_chain_uint256_from(400);
        l_out_cond_delegate->header.srv_uid = l_srv_uid;
        l_out_cond_delegate->subtype.srv_stake_pos_delegate.signer_node_addr = l_node_addr;
        l_out_cond_delegate->subtype.srv_stake_pos_delegate.signing_addr = l_addr;
        dap_chain_datum_tx_add_item(&l_tx, l_out_cond_delegate);
        DAP_DELETE(l_out_cond_delegate);
    }
    
    // 4. OUT_COND with SRV_STAKE_LOCK subtype
    l_srv_uid.uint64 = DAP_CHAIN_NET_SRV_STAKE_LOCK_ID;
    dap_chain_tx_out_cond_t *l_out_cond_lock = dap_chain_datum_tx_item_out_cond_create_srv_stake_lock(
        l_srv_uid, dap_chain_uint256_from(500), 3600, dap_chain_uint256_from(5));
    if (l_out_cond_lock) {
        l_out_cond_lock->header.item_type = TX_ITEM_TYPE_OUT_COND;
        dap_chain_datum_tx_add_item(&l_tx, l_out_cond_lock);
        DAP_DELETE(l_out_cond_lock);
    }
    
    // 5. OUT_COND with FEE subtype
    dap_chain_tx_out_cond_t *l_out_cond_fee = dap_chain_datum_tx_item_out_cond_create_fee(dap_chain_uint256_from(10));
    if (l_out_cond_fee) {
        l_out_cond_fee->header.item_type = TX_ITEM_TYPE_OUT_COND;
        dap_chain_datum_tx_add_item(&l_tx, l_out_cond_fee);
        DAP_DELETE(l_out_cond_fee);
    }
    
    // 6. OUT_COND with WALLET_SHARED subtype
    dap_hash_fast_t l_pkey_hash = {};
    l_srv_uid.uint64 = DAP_CHAIN_NET_SRV_WALLET_SHARED_ID;
    dap_chain_tx_out_cond_t *l_out_cond_shared = dap_chain_datum_tx_item_out_cond_create_wallet_shared(
        l_srv_uid, dap_chain_uint256_from(600), 2, &l_pkey_hash, 1, "shared_wallet");
    if (l_out_cond_shared) {
        l_out_cond_shared->header.item_type = TX_ITEM_TYPE_OUT_COND;
        dap_chain_datum_tx_add_item(&l_tx, l_out_cond_shared);
        DAP_DELETE(l_out_cond_shared);
    }
    
    // Add OUT_EXT item
    dap_chain_tx_out_ext_t *l_out_ext_item = dap_chain_datum_tx_item_out_ext_create(&l_addr, l_value, "EXT_TOKEN");
    if (l_out_ext_item) {
        l_out_ext_item->header.type = TX_ITEM_TYPE_OUT_EXT;
        dap_chain_datum_tx_add_item(&l_tx, l_out_ext_item);
        DAP_DELETE(l_out_ext_item);
    }
    
    // Add OUT_STD item
    dap_chain_tx_out_std_t *l_out_std_item = dap_chain_datum_tx_item_out_std_create(&l_addr, l_value, "STD_TOKEN", 0);
    if (l_out_std_item) {
        l_out_std_item->type = TX_ITEM_TYPE_OUT_STD;
        dap_chain_datum_tx_add_item(&l_tx, l_out_std_item);
        DAP_DELETE(l_out_std_item);
    }
    
    // Add PKEY item
    l_key = dap_enc_key_new(DAP_ENC_KEY_TYPE_SIG_BLISS);
    if (l_key) {
        dap_pkey_t *l_pkey = dap_pkey_from_enc_key(l_key);
        if (l_pkey) {
            size_t l_pkey_size = sizeof(dap_chain_tx_pkey_t) + l_pkey->header.size;
            dap_chain_tx_pkey_t *l_pkey_item = DAP_MALLOC(l_pkey_size);
            if (l_pkey_item) {
                l_pkey_item->type = TX_ITEM_TYPE_PKEY;
                l_pkey_item->header.type = l_pkey->header.type;
                l_pkey_item->header.size = l_pkey->header.size;
                memcpy(l_pkey_item->pkey, l_pkey->pkey, l_pkey->header.size);
                dap_chain_datum_tx_add_item(&l_tx, l_pkey_item);
                DAP_DELETE(l_pkey_item);
            }
        }
        dap_enc_key_delete(l_key);
    }
       
    // Add RECEIPT_OLD item
    dap_chain_datum_tx_receipt_old_t *l_receipt_old_item = DAP_NEW_Z(dap_chain_datum_tx_receipt_old_t);
    if (l_receipt_old_item) {
        l_receipt_old_item->type = TX_ITEM_TYPE_RECEIPT_OLD;
        l_receipt_old_item->size = sizeof(dap_chain_datum_tx_receipt_old_t);
        l_receipt_old_item->exts_size = 0;
        l_receipt_old_item->receipt_info.value_datoshi = dap_chain_uint256_from(100);
        l_receipt_old_item->receipt_info.units = 1;
        l_receipt_old_item->receipt_info.srv_uid.uint64 = 1;
        l_receipt_old_item->receipt_info.units_type.enm = SERV_UNIT_SEC;
        dap_chain_datum_tx_add_item(&l_tx, l_receipt_old_item);
        DAP_DELETE(l_receipt_old_item);
    }
    
    // Add RECEIPT item
    dap_chain_datum_tx_receipt_t *l_receipt_item = DAP_NEW_Z(dap_chain_datum_tx_receipt_t);
    if (l_receipt_item) {
        l_receipt_item->type = TX_ITEM_TYPE_RECEIPT;
        l_receipt_item->size = sizeof(dap_chain_datum_tx_receipt_t);
        l_receipt_item->exts_size = 0;
        l_receipt_item->receipt_info.value_datoshi = dap_chain_uint256_from(200);
        l_receipt_item->receipt_info.units = 2;
        l_receipt_item->receipt_info.srv_uid.uint64 = 2;
        l_receipt_item->receipt_info.units_type.enm = SERV_UNIT_SEC;
        dap_chain_datum_tx_add_item(&l_tx, l_receipt_item);
        DAP_DELETE(l_receipt_item);
    }
    
    // Add TSD item
    const char *l_tsd_data = "test_data";
    dap_chain_tx_tsd_t *l_tsd_item = dap_chain_datum_tx_item_tsd_create((void*)l_tsd_data, 1, strlen(l_tsd_data));
    if (l_tsd_item) {
        l_tsd_item->header.type = TX_ITEM_TYPE_TSD;
        dap_chain_datum_tx_add_item(&l_tx, l_tsd_item);
        DAP_DELETE(l_tsd_item);
    }
    
    // Add VOTING item
    dap_chain_tx_voting_t *l_voting_item = DAP_NEW_Z(dap_chain_tx_voting_t);
    if (l_voting_item) {
        l_voting_item->type = TX_ITEM_TYPE_VOTING;
        dap_chain_datum_tx_add_item(&l_tx, l_voting_item);
        DAP_DELETE(l_voting_item);
    }
    
    // Add VOTE item
    dap_chain_tx_vote_t *l_vote_item = DAP_NEW_Z(dap_chain_tx_vote_t);
    if (l_vote_item) {
        l_vote_item->type = TX_ITEM_TYPE_VOTE;
        l_vote_item->voting_hash = l_prev_hash;
        l_vote_item->answer_idx = 0;
        dap_chain_datum_tx_add_item(&l_tx, l_vote_item);
        DAP_DELETE(l_vote_item);
    }
    
    // Add EVENT item
    dap_chain_tx_item_event_t *l_event_item = dap_chain_datum_tx_event_create("test_group", 1);
    if (l_event_item) {
        l_event_item->type = TX_ITEM_TYPE_EVENT;
        dap_chain_datum_tx_add_item(&l_tx, l_event_item);
        DAP_DELETE(l_event_item);
    }
    
    // Add SIG item
    static const uint8_t l_sig_data[64] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00};
    size_t l_sig_size = sizeof(dap_chain_tx_sig_t) + sizeof(l_sig_data);
    dap_chain_tx_sig_t *l_sig_item = DAP_MALLOC(l_sig_size);
    if (l_sig_item) {
        l_sig_item->header.type = TX_ITEM_TYPE_SIG;
        l_sig_item->header.version = 1;
        l_sig_item->header.sig_size = sizeof(l_sig_data);
        memcpy(l_sig_item->sig, l_sig_data, sizeof(l_sig_data));
        dap_chain_datum_tx_add_item(&l_tx, l_sig_item);
        DAP_DELETE(l_sig_item);
    }
    
    return l_tx;
}

/**
 * @brief Compare two JSON objects for equality
 * @param[in] a_obj1 First JSON object
 * @param[in] a_obj2 Second JSON object
 * @return true if objects are equal, false otherwise
 */
static bool compare_json_objects(json_object *a_obj1, json_object *a_obj2)
{
    if (!a_obj1 || !a_obj2) {
        return a_obj1 == a_obj2;
    }
    
    const char *l_str1 = json_object_to_json_string(a_obj1);
    const char *l_str2 = json_object_to_json_string(a_obj2);
    
    if (!l_str1 || !l_str2) {
        return l_str1 == l_str2;
    }
    
    return strcmp(l_str1, l_str2) == 0;
}

/**
 * @brief Test dap_chain_datum_dump_tx_json functions
 */
static void test_dap_chain_datum_dump_tx_json(void)
{
    log_it(L_INFO, "Testing dap_chain_datum_dump_tx_json functions...");
    
    dap_chain_datum_tx_t *l_tx = create_test_transaction();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create test transaction");
        return;
    }
    
    dap_hash_fast_t l_tx_hash = {};
    dap_chain_datum_calc_hash((dap_chain_datum_t*)l_tx, &l_tx_hash);
    dap_chain_net_id_t l_net_id = {.uint64 = 1};
    
    // Test old implementation
    json_object *l_json_old = json_object_new_object();
    bool l_result_old = dap_chain_datum_dump_tx_json_old(NULL, l_tx, "TEST", l_json_old, "hex", &l_tx_hash, l_net_id, 2);
    
    // Test new implementation
    json_object *l_json_new = json_object_new_object();
    bool l_result_new = dap_chain_datum_dump_tx_json(NULL, l_tx, "TEST", l_json_new, "hex", &l_tx_hash, l_net_id, 2);
    
    // Compare results
    if (l_result_old != l_result_new) {
        log_it(L_ERROR, "Function return values differ: old=%d, new=%d", l_result_old, l_result_new);
    } else {
        log_it(L_INFO, "Function return values match: %d", l_result_old);
    }
    
    if (!compare_json_objects(l_json_old, l_json_new)) {
        log_it(L_ERROR, "JSON outputs differ!");
        log_it(L_ERROR, "Old output: %s", json_object_to_json_string(l_json_old));
        log_it(L_ERROR, "New output: %s", json_object_to_json_string(l_json_new));
    } else {
        log_it(L_INFO, "JSON outputs match");
    }
    
    // Cleanup
    json_object_put(l_json_old);
    json_object_put(l_json_new);
    dap_chain_datum_tx_delete(l_tx);
}


/**
 * @brief Main test function for transaction JSON serialization
 */
void dap_chain_datum_tx_json_test_run(void)
{
    dap_print_module_name("dap_chain_datum_tx_json");
    
    test_dap_chain_datum_dump_tx_json();
} 