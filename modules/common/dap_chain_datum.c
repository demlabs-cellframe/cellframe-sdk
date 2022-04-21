/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

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
#include <string.h>

#include "dap_common.h"
#include "dap_time.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_hashtree_roots.h"
#include "dap_chain_datum_token.h"
#include "dap_enc_base58.h"

#define LOG_TAG "dap_chain_datum"

/**
 * @brief dap_chain_datum_create
 * @param a_type_id
 * @param a_data
 * @param a_data_size
 * @return
 */
dap_chain_datum_t * dap_chain_datum_create(uint16_t a_type_id, const void * a_data, size_t a_data_size)
{
   dap_chain_datum_t * l_datum = DAP_NEW_Z_SIZE(dap_chain_datum_t, sizeof(l_datum->header)+ a_data_size);
   memcpy (l_datum->data,a_data,a_data_size);
   l_datum->header.type_id = a_type_id;
   l_datum->header.data_size = (uint32_t) a_data_size;
   l_datum->header.version_id = DAP_CHAIN_DATUM_VERSION;
   l_datum->header.ts_create =(uint64_t) time(NULL);
   return  l_datum;
}

void s_datum_token_dump_tsd(dap_string_t *a_str_out, dap_chain_datum_token_t *a_token, size_t a_token_size, const char *a_hash_out_type)
{
    dap_tsd_t *l_tsd = dap_chain_datum_token_tsd_get(a_token, a_token_size);
    if (l_tsd == NULL) {
        dap_string_append_printf(a_str_out,"<CORRUPTED TSD SECTION>\n");
        return;
    }
    size_t l_offset = 0;
    size_t l_offset_max = 0;
    switch (a_token->type) {
    case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL:
        l_offset_max = a_token->header_private_decl.tsd_total_size; break;
    case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE:
        l_offset_max = a_token->header_private_update.tsd_total_size; break;
    case DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL:
        l_offset_max = a_token->header_native_decl.tsd_total_size; break;
    case DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_UPDATE:
        l_offset_max = a_token->header_native_update.tsd_total_size; break;
    default: break;
    }
    while (l_offset < l_offset_max) {
        if ((l_tsd->size+l_offset) > l_offset_max) {
            log_it(L_WARNING, "<CORRUPTED TSD> too big size %u when left maximum %zu",
                   l_tsd->size, l_offset_max - l_offset);
            return;
        }
        switch( l_tsd->type){
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_SET_FLAGS:
                dap_string_append_printf(a_str_out,"flags_set: ");
                dap_chain_datum_token_flags_dump(a_str_out,
                                                 dap_tsd_get_scalar(l_tsd, uint16_t));
            break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS:
                dap_string_append_printf(a_str_out,"flags_unset: ");
                dap_chain_datum_token_flags_dump(a_str_out,
                                                 dap_tsd_get_scalar(l_tsd, uint16_t));
            break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY: // 256
                dap_string_append_printf(a_str_out,"total_supply: %s\n",
                                    dap_chain_balance_print(
                                            dap_tsd_get_scalar(l_tsd, uint256_t)));
            break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY_OLD: // 128
                dap_string_append_printf(a_str_out,"total_supply: %s\n",
                                    dap_chain_balance_print(GET_256_FROM_128(
                                        dap_tsd_get_scalar(l_tsd, uint128_t))));
            break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID :
                dap_string_append_printf(a_str_out,"total_signs_valid: %u\n",
                                         dap_tsd_get_scalar(l_tsd, uint16_t) );
            break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_ADD :
                if(l_tsd->size == sizeof(dap_chain_hash_fast_t) ){
                    char *l_hash_str;
                    if(!dap_strcmp(a_hash_out_type, "hex") || !dap_strcmp(a_hash_out_type, "content_hash") )
                        l_hash_str = dap_chain_hash_fast_to_str_new((dap_chain_hash_fast_t*) l_tsd->data);
                    else
                        l_hash_str = dap_enc_base58_encode_hash_to_str((dap_chain_hash_fast_t*) l_tsd->data);
                    dap_string_append_printf(a_str_out,"total_signs_add: %s\n", l_hash_str);
                    DAP_DELETE( l_hash_str );
                }else
                    dap_string_append_printf(a_str_out,"total_signs_add: <WRONG SIZE %u>\n", l_tsd->size);
            break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_REMOVE :
                if(l_tsd->size == sizeof(dap_chain_hash_fast_t) ){
                    char *l_hash_str;
                    if(!dap_strcmp(a_hash_out_type,"hex")|| !dap_strcmp(a_hash_out_type, "content_hash"))
                        l_hash_str = dap_chain_hash_fast_to_str_new((dap_chain_hash_fast_t*) l_tsd->data);
                    else
                        l_hash_str = dap_enc_base58_encode_hash_to_str((dap_chain_hash_fast_t*) l_tsd->data);
                    dap_string_append_printf(a_str_out,"total_signs_remove: %s\n", l_hash_str );
                    DAP_DELETE( l_hash_str );
                }else
                    dap_string_append_printf(a_str_out,"total_signs_add: <WRONG SIZE %u>\n", l_tsd->size);
            break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD  :
                dap_string_append_printf(a_str_out,"datum_type_allowed_add: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_REMOVE  :
                dap_string_append_printf(a_str_out,"datum_type_allowed_remove: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_ADD  :
                dap_string_append_printf(a_str_out,"datum_type_blocked_add: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_REMOVE:
                dap_string_append_printf(a_str_out,"datum_type_blocked_remove: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD:
                dap_string_append_printf(a_str_out,"tx_sender_allowed_add: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_REMOVE:
                dap_string_append_printf(a_str_out,"tx_sender_allowed_remove: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD:
                dap_string_append_printf(a_str_out,"tx_sender_blocked_add: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_REMOVE:
                dap_string_append_printf(a_str_out,"tx_sender_blocked_remove: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD:
                dap_string_append_printf(a_str_out,"tx_receiver_allowed_add: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_REMOVE:
                dap_string_append_printf(a_str_out,"tx_receiver_allowed: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD:
                dap_string_append_printf(a_str_out, "tx_receiver_blocked_add: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_REMOVE:
                dap_string_append_printf(a_str_out, "tx_receiver_blocked_remove: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            break;
            default: dap_string_append_printf(a_str_out, "<0x%04hX>: <size %u>\n", l_tsd->type, l_tsd->size);
        }
        l_offset += dap_tsd_size(l_tsd);
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
bool dap_chain_datum_dump_tx(dap_chain_datum_tx_t *a_datum,
                             const char *a_ticker,
                             dap_string_t *a_str_out,
                             const char *a_hash_out_type,
                             dap_hash_fast_t *a_tx_hash)
{
    dap_time_t l_ts_create = (dap_time_t)a_datum->header.ts_created;
    bool l_is_first = false;
    dap_chain_tx_in_t *l_in_item = (dap_chain_tx_in_t *)dap_chain_datum_tx_item_get(a_datum, NULL, TX_ITEM_TYPE_IN, NULL);
    if (l_in_item && dap_hash_fast_is_blank(&l_in_item->header.tx_prev_hash))
        l_is_first = true;
    char l_tmp_buf[70];
    char *l_hash_str = NULL;
    if(!dap_strcmp(a_hash_out_type, "hex"))
        l_hash_str = dap_chain_hash_fast_to_str_new(a_tx_hash);
    else
        l_hash_str = dap_enc_base58_encode_hash_to_str(a_tx_hash);
    dap_string_append_printf(a_str_out, "transaction:%s hash: %s\n TS Created: %s%s%s\n Items:\n",
                              l_is_first ? " (emit)" : "", l_hash_str, dap_ctime_r(&l_ts_create, l_tmp_buf),
                              a_ticker ? " Token ticker: " : "", a_ticker ? a_ticker : "");
    DAP_DELETE(l_hash_str);
    uint32_t l_tx_items_count = 0;
    uint32_t l_tx_items_size = a_datum->header.tx_items_size;
    dap_sign_t *l_sign_tmp;
    dap_chain_hash_fast_t l_pkey_hash_tmp;
    dap_hash_fast_t *l_hash_tmp = NULL;
    dap_pkey_t *l_pkey_tmp;
    while (l_tx_items_count < l_tx_items_size) {
        uint8_t *item = a_datum->tx_items + l_tx_items_count;
        size_t l_item_tx_size = dap_chain_datum_item_tx_get_size(item);
        switch(dap_chain_datum_tx_item_get_type(item)){
        case TX_ITEM_TYPE_IN:
            l_hash_tmp = &((dap_chain_tx_in_t*)item)->header.tx_prev_hash;
            if (dap_hash_fast_is_blank(l_hash_tmp)) {
                l_hash_str = dap_strdup("BLANK");
            } else {
                if (!dap_strcmp(a_hash_out_type, "hex"))
                    l_hash_str = dap_chain_hash_fast_to_str_new(l_hash_tmp);
                else
                    l_hash_str = dap_enc_base58_encode_hash_to_str(l_hash_tmp);
            }
            dap_string_append_printf(a_str_out, "\t IN:\nTx_prev_hash: %s\n"
                                                "\t\t Tx_out_prev_idx: %u\n",
                                        l_hash_str,
                                        ((dap_chain_tx_in_t*)item)->header.tx_out_prev_idx);
            DAP_DELETE(l_hash_str);
            break;
        case TX_ITEM_TYPE_OUT_OLD: {
            char *l_value_str = dap_chain_balance_to_coins(dap_chain_uint256_from(
                                                               ((dap_chain_tx_out_old_t*)item)->header.value));
            char *l_addr_str = dap_chain_addr_to_str(&((dap_chain_tx_out_old_t*)item)->addr);
            dap_string_append_printf(a_str_out, "\t OUT OLD (64):\n"
                                                "\t\t Value: %s (%"DAP_UINT64_FORMAT_U")\n"
                                                "\t\t Address: %s\n",
                                        l_value_str,
                                        ((dap_chain_tx_out_old_t*)item)->header.value,
                                        l_addr_str);
            DAP_DELETE(l_value_str);
            DAP_DELETE(l_addr_str);
        } break;
        case TX_ITEM_TYPE_OUT: { // 256
            char *l_value_str = dap_chain_balance_print(((dap_chain_tx_out_t*)item)->header.value);
            char *l_coins_str = dap_chain_balance_to_coins(((dap_chain_tx_out_t*)item)->header.value);
            char *l_addr_str = dap_chain_addr_to_str(&((dap_chain_tx_out_t*)item)->addr);
            dap_string_append_printf(a_str_out, "\t OUT:\n"
                                                "\t\t Value: %s (%s)\n"
                                                "\t\t Address: %s\n",
                                        l_coins_str,
                                        l_value_str,
                                        l_addr_str);
            DAP_DELETE(l_value_str);
            DAP_DELETE(l_coins_str);
            DAP_DELETE(l_addr_str);
        } break;
        case TX_ITEM_TYPE_TOKEN: {
            l_hash_tmp = &((dap_chain_tx_token_t*)item)->header.token_emission_hash;
            if (!dap_strcmp(a_hash_out_type, "hex"))
                l_hash_str = dap_chain_hash_fast_to_str_new(l_hash_tmp);
            else
                l_hash_str = dap_enc_base58_encode_hash_to_str(l_hash_tmp);
            dap_string_append_printf(a_str_out, "\t TOKEN:\n"
                                                "\t\t ticker: %s \n"
                                                "\t\t token_emission_hash: %s\n"
                                                "\t\t token_emission_chain_id: 0x%016"DAP_UINT64_FORMAT_x"\n",
                                                ((dap_chain_tx_token_t*)item)->header.ticker,
                                                l_hash_str,
                                                ((dap_chain_tx_token_t*)item)->header.token_emission_chain_id.uint64);
            DAP_DELETE(l_hash_str);
        } break;
        case TX_ITEM_TYPE_TOKEN_EXT: {
            l_hash_tmp = &((dap_chain_tx_token_ext_t*)item)->header.ext_tx_hash;
            if (!dap_strcmp(a_hash_out_type, "hex"))
                l_hash_str = dap_chain_hash_fast_to_str_new(l_hash_tmp);
            else
                l_hash_str = dap_enc_base58_encode_hash_to_str(l_hash_tmp);
            dap_string_append_printf(a_str_out, "\t TOKEN EXT:\n"
                                         "\t\t Version: %u\n"
                                         "\t\t Ticker: %s\n"
                                         "\t\t Ext chain id: 0x%016"DAP_UINT64_FORMAT_x"\n"
                                         "\t\t Ext net id: 0x%016"DAP_UINT64_FORMAT_x"\n"
                                         "\t\t Ext tx hash: %s\n"
                                         "\t\t Ext tx out idx: %u\n",
                                     ((dap_chain_tx_token_ext_t*)item)->header.version,
                                     ((dap_chain_tx_token_ext_t*)item)->header.ticker,
                                     ((dap_chain_tx_token_ext_t*)item)->header.ext_chain_id.uint64,
                                     ((dap_chain_tx_token_ext_t*)item)->header.ext_net_id.uint64,
                                     l_hash_str,
                                     ((dap_chain_tx_token_ext_t*)item)->header.ext_tx_out_idx);
            DAP_DELETE(l_hash_str);
        } break;
        case TX_ITEM_TYPE_SIG: {
            l_sign_tmp = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)item);
            dap_sign_get_information(l_sign_tmp, a_str_out, a_hash_out_type);
        } break;
        case TX_ITEM_TYPE_RECEIPT: {
            char *l_value_str = dap_chain_balance_print(
                        ((dap_chain_datum_tx_receipt_t*)item)->receipt_info.value_datoshi);
            char *l_coins_str = dap_chain_balance_to_coins(
                        ((dap_chain_datum_tx_receipt_t*)item)->receipt_info.value_datoshi);
            serv_unit_enum_t l_unit = ((dap_chain_datum_tx_receipt_t*)item)->receipt_info.units_type.enm;
            dap_string_append_printf(a_str_out, "\t Receipt:\n"
                                                "\t\t size: %"DAP_UINT64_FORMAT_U"\n"
                                                "\t\t ext size: %"DAP_UINT64_FORMAT_U"\n"
                                                "\t\t Info:"
                                                "\t\t\t   units: 0x%016"DAP_UINT64_FORMAT_x"\n"
                                                "\t\t\t   uid: 0x%016"DAP_UINT64_FORMAT_x"\n"
                                                "\t\t\t   units type: %s \n"
                                                "\t\t\t   value: %s (%s)\n",
                                     ((dap_chain_datum_tx_receipt_t*)item)->size,
                                     ((dap_chain_datum_tx_receipt_t*)item)->exts_size,
                                     ((dap_chain_datum_tx_receipt_t*)item)->receipt_info.units,
                                     ((dap_chain_datum_tx_receipt_t*)item)->receipt_info.srv_uid.uint64,
                                     serv_unit_enum_to_str(&l_unit),
                                     l_coins_str,
                                     l_value_str);
            if (((dap_chain_datum_tx_receipt_t*)item)->exts_size == sizeof(dap_sign_t) + sizeof(dap_sign_t)){
                dap_sign_t *l_provider = DAP_NEW_Z(dap_sign_t);
                memcpy(l_provider, ((dap_chain_datum_tx_receipt_t*)item)->exts_n_signs, sizeof(dap_sign_t));
                dap_sign_t *l_client = DAP_NEW_Z(dap_sign_t);
                memcpy(l_client,
                       ((dap_chain_datum_tx_receipt_t*)item)->exts_n_signs + sizeof(dap_sign_t),
                       sizeof(dap_sign_t));
                dap_string_append_printf(a_str_out, "Exts:\n"
                                                    "   Provider:\n");
                dap_sign_get_information(l_provider, a_str_out, a_hash_out_type);
                dap_string_append_printf(a_str_out, "   Client:\n");
                dap_sign_get_information(l_client, a_str_out, a_hash_out_type);
            } else if (((dap_chain_datum_tx_receipt_t*)item)->exts_size == sizeof(dap_sign_t)) {
                dap_sign_t *l_provider = DAP_NEW_Z(dap_sign_t);
                memcpy(l_provider, ((dap_chain_datum_tx_receipt_t*)item)->exts_n_signs, sizeof(dap_sign_t));
                dap_string_append_printf(a_str_out, "Exts:\n"
                                                    "   Provider:\n");
                dap_sign_get_information(l_provider, a_str_out, a_hash_out_type);
            }
            DAP_DELETE(l_value_str);
            DAP_DELETE(l_coins_str);
        } break;
        case TX_ITEM_TYPE_PKEY: {
            l_pkey_tmp = (dap_pkey_t*)((dap_chain_tx_pkey_t*)item)->pkey;
            dap_hash_fast(l_pkey_tmp->pkey, l_pkey_tmp->header.size, &l_pkey_hash_tmp);
            if (!dap_strcmp(a_hash_out_type, "hex"))
                l_hash_str = dap_chain_hash_fast_to_str_new(&l_pkey_hash_tmp);
            else
                l_hash_str = dap_enc_base58_encode_hash_to_str(&l_pkey_hash_tmp);
            dap_string_append_printf(a_str_out, "\t PKey: \n"
                                                "\t\t SIG type: %s\n"
                                                "\t\t SIG size: %u\n"
                                                "\t\t Sequence number: %u \n"
                                                "\t\t Key: \n"
                                                "\t\t\t Type: %s\n"
                                                "\t\t\t Size: %u\n"
                                                "\t\t\t Hash: %s\n",
                                     dap_sign_type_to_str(((dap_chain_tx_pkey_t*)item)->header.sig_type),
                                     ((dap_chain_tx_pkey_t*)item)->header.sig_size,
                                     ((dap_chain_tx_pkey_t*)item)->seq_no,
                                     dap_pkey_type_to_str(l_pkey_tmp->header.type),
                                     l_pkey_tmp->header.size,
                                     l_hash_str);
            DAP_DELETE(l_hash_str);
        } break;
        case TX_ITEM_TYPE_IN_COND:
            l_hash_tmp = &((dap_chain_tx_in_cond_t*)item)->header.tx_prev_hash;
            if (!dap_strcmp(a_hash_out_type, "hex"))
                l_hash_str = dap_chain_hash_fast_to_str_new(l_hash_tmp);
            else
                l_hash_str = dap_enc_base58_encode_hash_to_str(l_hash_tmp);
            dap_string_append_printf(a_str_out, "\t IN COND:\n\t\tReceipt_idx: %u\n"
                                                "\t\t Tx_prev_hash: %s\n"
                                                "\t\t Tx_out_prev_idx: %u\n",
                                     ((dap_chain_tx_in_cond_t*)item)->header.receipt_idx,
                                     l_hash_str,
                                     ((dap_chain_tx_in_cond_t*)item)->header.tx_out_prev_idx);
            DAP_DELETE(l_hash_str);
            break;
        case TX_ITEM_TYPE_OUT_COND: {
            char *l_value_str = dap_chain_balance_print(((dap_chain_tx_out_cond_t*)item)->header.value);
            char *l_coins_str = dap_chain_balance_to_coins(((dap_chain_tx_out_cond_t*)item)->header.value);
            dap_string_append_printf(a_str_out, "\t OUT COND:\n"
                                                "\t Header:\n"
                                                "\t\t\t ts_expires: %s\t"
                                                "\t\t\t value: %s (%s)\n"
                                                "\t\t\t subtype: %s\n"
                                                "\t\t SubType:\n",
                                     dap_ctime_r((dap_time_t*)((dap_chain_tx_out_cond_t*)item)->header.ts_expires, l_tmp_buf),
                                     l_coins_str,
                                     l_value_str,
                                     dap_chain_tx_out_cond_subtype_to_str(((dap_chain_tx_out_cond_t*)item)->header.subtype));
            DAP_DELETE(l_value_str);
            DAP_DELETE(l_coins_str);
            switch (((dap_chain_tx_out_cond_t*)item)->header.subtype) {
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY: {
                    char *l_value_str = dap_chain_balance_print(((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.unit_price_max_datoshi);
                    char *l_coins_str = dap_chain_balance_to_coins(((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.unit_price_max_datoshi);
                    l_hash_tmp = &((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.pkey_hash;
                    if (!dap_strcmp(a_hash_out_type, "hex"))
                        l_hash_str = dap_chain_hash_fast_to_str_new(l_hash_tmp);
                    else
                        l_hash_str = dap_enc_base58_encode_hash_to_str(l_hash_tmp);
                    dap_string_append_printf(a_str_out, "\t\t\t unit: 0x%08x\n"
                                                        "\t\t\t uid: 0x%016"DAP_UINT64_FORMAT_x"\n"
                                                        "\t\t\t pkey: %s\n"
                                                        "\t\t\t max price: %s (%s) \n",
                                             ((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.unit.uint32,
                                             ((dap_chain_tx_out_cond_t*)item)->header.srv_uid.uint64,
                                             l_hash_str,
                                             l_coins_str,
                                             l_value_str);
                    DAP_DELETE(l_hash_str);
                    DAP_DELETE(l_value_str);
                    DAP_DELETE(l_coins_str);
                } break;
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE: {
                    char *l_coins_str = dap_chain_balance_to_coins(((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake.fee_value);
                    char *l_addr_str = dap_chain_addr_to_str(&((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake.fee_addr);
                    dap_string_append_printf(a_str_out, "\t\t\t uid: 0x%016"DAP_UINT64_FORMAT_x"\n"
                                                        "\t\t\t addr: %s\n"
                                                        "\t\t\t value: %s",
                                            ((dap_chain_tx_out_cond_t*)item)->header.srv_uid.uint64,
                                            l_addr_str,
                                            l_coins_str);
                    DAP_DELETE(l_addr_str);
                    DAP_DELETE(l_coins_str);
                } break;
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE: {
                    char *l_value_str = dap_chain_balance_print(((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.value);
                    char *l_coins_str = dap_chain_balance_to_coins(((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.value);
                    dap_string_append_printf(a_str_out, "\t\t\t uid: 0x%016"DAP_UINT64_FORMAT_x"\n"
                                                        "\t\t\t net id: 0x%016"DAP_UINT64_FORMAT_x"\n"
                                                        "\t\t\t token: %s\n"
                                                        "\t\t\t value: %s (%s)\n",
                                             ((dap_chain_tx_out_cond_t*)item)->header.srv_uid.uint64,
                                             ((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.net_id.uint64,
                                             ((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.token,
                                             l_coins_str,
                                             l_value_str);
                    DAP_DELETE(l_value_str);
                    DAP_DELETE(l_coins_str);
                } break;
                default: break;
            }
        } break;
        case TX_ITEM_TYPE_OUT_EXT: {
            char *l_value_str = dap_chain_balance_print(((dap_chain_tx_out_ext_t*)item)->header.value);
            char *l_coins_str = dap_chain_balance_to_coins(((dap_chain_tx_out_ext_t*)item)->header.value);
            char *l_addr_str = dap_chain_addr_to_str(&((dap_chain_tx_out_ext_t*)item)->addr);
            dap_string_append_printf(a_str_out, "\t OUT EXT:\n"
                                                "\t\t Addr: %s\n"
                                                "\t\t Token: %s\n"
                                                "\t\t Value: %s (%s)\n",
                                     l_addr_str,
                                     ((dap_chain_tx_out_ext_t*)item)->token,
                                     l_coins_str,
                                     l_value_str);
            DAP_DELETE(l_addr_str);
            DAP_DELETE(l_value_str);
            DAP_DELETE(l_coins_str);
        } break;
        default:
            dap_string_append_printf(a_str_out, " This transaction have unknown item type \n");
            break;
        }
        l_tx_items_count += l_item_tx_size;
        // Freeze protection
        if(!l_item_tx_size)
        {
            break;
        }

    }
    dap_string_append_printf(a_str_out, "\n");
    return true;
}

/**
 * @brief dap_chain_net_dump_datum
 * process datum verification process. Can be:
 * if DAP_CHAIN_DATUM_TX, called dap_chain_ledger_tx_add_check
 * if DAP_CHAIN_DATUM_TOKEN_DECL, called dap_chain_ledger_token_decl_add_check
 * if DAP_CHAIN_DATUM_TOKEN_EMISSION, called dap_chain_ledger_token_emission_add_check
 * @param a_str_out
 * @param a_datum
 */
void dap_chain_datum_dump(dap_string_t *a_str_out, dap_chain_datum_t *a_datum, const char *a_hash_out_type)
{
    if( a_datum == NULL){
        dap_string_append_printf(a_str_out,"==Datum is NULL\n");
        return;
    }
    dap_hash_fast_t l_datum_hash;
    dap_hash_fast(a_datum->data, a_datum->header.data_size, &l_datum_hash);
    char *l_hash_str = NULL;
    if(!dap_strcmp(a_hash_out_type, "hex"))
        l_hash_str = dap_chain_hash_fast_to_str_new(&l_datum_hash);
    else
        l_hash_str = dap_enc_base58_encode_hash_to_str(&l_datum_hash);
    switch (a_datum->header.type_id) {
        case DAP_CHAIN_DATUM_TOKEN_DECL: {
            size_t l_token_size = a_datum->header.data_size;
            dap_chain_datum_token_t * l_token = dap_chain_datum_token_read(a_datum->data, &l_token_size);
            if(l_token_size < sizeof(dap_chain_datum_token_t)){
                dap_string_append_printf(a_str_out,"==Datum has incorrect size. Only %zu, while at least %zu is expected\n",
                                         l_token_size, sizeof(dap_chain_datum_token_t));
                return;
            }
            dap_string_append_printf(a_str_out,"=== Datum Token Declaration ===\n");
            dap_string_append_printf(a_str_out, "hash: %s\n", l_hash_str);
            dap_string_append_printf(a_str_out, "ticker: %s\n", l_token->ticker);
            dap_string_append_printf(a_str_out, "size: %zd\n", l_token_size);
            switch (l_token->type) {
                case DAP_CHAIN_DATUM_TOKEN_TYPE_SIMPLE:{
                    char *l_value_str = dap_chain_balance_print(l_token->total_supply);
                    dap_string_append(a_str_out, "type: SIMPLE\n");
                    dap_string_append_printf(a_str_out, "sign_total: %hu\n", l_token->signs_total );
                    dap_string_append_printf(a_str_out, "sign_valid: %hu\n", l_token->signs_valid );
                    dap_string_append_printf(a_str_out, "total_supply: %s\n", l_value_str);
                    size_t l_certs_field_size = l_token_size - sizeof(*l_token);
                    dap_chain_datum_token_certs_dump(a_str_out, l_token->data_n_tsd,
                                                     l_certs_field_size, a_hash_out_type);
                    DAP_DELETE(l_value_str);
                }break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE:{
                    dap_string_append(a_str_out,"type: PRIVATE_UPDATE\n");
                    s_datum_token_dump_tsd(a_str_out, l_token, l_token_size, a_hash_out_type);
                }break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL:{
                    dap_string_append(a_str_out,"type: PRIVATE\n");
                    dap_string_append(a_str_out,"flags: ");
                    dap_chain_datum_token_flags_dump(a_str_out, l_token->header_private_decl.flags);
                    s_datum_token_dump_tsd(a_str_out, l_token, l_token_size, a_hash_out_type);
                    size_t l_certs_field_size = l_token_size - sizeof(*l_token) - l_token->header_private_decl.tsd_total_size;
                    dap_chain_datum_token_certs_dump(a_str_out, l_token->data_n_tsd + l_token->header_private_decl.tsd_total_size,
                                                     l_certs_field_size, a_hash_out_type);
                }break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_UPDATE:{
                    dap_string_append_printf(a_str_out,"type: CF20_UPDATE\n");
                    s_datum_token_dump_tsd(a_str_out, l_token, l_token_size, a_hash_out_type);
                }break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL:{
                    dap_string_append(a_str_out, "type: CF20\n");
                    dap_string_append(a_str_out, "decimals: 18\n");
                    dap_string_append_printf(a_str_out, "auth signs (valid/total) %u/%u\n", l_token->signs_valid, l_token->signs_total);
                    dap_string_append(a_str_out, "flags: ");
                    dap_chain_datum_token_flags_dump(a_str_out, l_token->header_native_decl.flags);
                    s_datum_token_dump_tsd(a_str_out, l_token, l_token_size, a_hash_out_type);
                    size_t l_certs_field_size = l_token_size - sizeof(*l_token) - l_token->header_native_decl.tsd_total_size;
                    dap_chain_datum_token_certs_dump(a_str_out, l_token->data_n_tsd + l_token->header_native_decl.tsd_total_size,
                                                     l_certs_field_size, a_hash_out_type);
                }break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_PUBLIC:{
                    dap_string_append(a_str_out,"type: PUBLIC\n");
                }break;
                default:
                    dap_string_append(a_str_out,"type: UNKNOWN\n");
            }
        } break;
        case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
            size_t l_emisssion_size = a_datum->header.data_size;
            dap_chain_datum_token_emission_t *l_emission = dap_chain_datum_emission_read(a_datum->data, &l_emisssion_size);
            char *l_value_str = dap_chain_balance_print(l_emission->hdr.value_256);
            char *l_coins_str = dap_chain_balance_to_coins(l_emission->hdr.value_256);
            char *l_addr_str = dap_chain_addr_to_str(&(l_emission->hdr.address));
            dap_string_append_printf(a_str_out, "emission: hash %s\n\t%s(%s) %s, type: %s, version: %d\n",
                                    l_hash_str,
                                    l_coins_str,
                                    l_value_str,
                                    l_emission->hdr.ticker,
                                    c_dap_chain_datum_token_emission_type_str[l_emission->hdr.type],
                                    l_emission->hdr.version);
            dap_string_append_printf(a_str_out, "  to addr: %s\n", l_addr_str);
            DAP_DELETE(l_value_str);
            DAP_DELETE(l_coins_str);
            DAP_DELETE(l_addr_str);
            switch (l_emission->hdr.type) {
                case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_UNDEFINED:
                    break;
                case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH:
                    dap_string_append_printf(a_str_out, "  signs_count: %d\n", l_emission->data.type_auth.signs_count);
                    dap_string_append_printf(a_str_out, "  tsd_total_size: %"DAP_UINT64_FORMAT_U"\n",
                                             l_emission->data.type_auth.tsd_total_size);

                    if (  ( (void *) l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size) >
                          ((void *) l_emission + l_emisssion_size) )
                    {
                        log_it(L_ERROR, "Illformed DATUM type %d, TSD section is out-of-buffer (%" DAP_UINT64_FORMAT_U " vs %zu)",
                            l_emission->hdr.type, l_emission->data.type_auth.tsd_total_size, l_emisssion_size);

                        dap_string_append_printf(a_str_out, "  Skip incorrect or illformed DATUM");
                        break;
                    }


                    dap_chain_datum_token_certs_dump(a_str_out, l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size,
                                                     l_emission->data.type_auth.size - l_emission->data.type_auth.tsd_total_size, a_hash_out_type);
                    break;
                case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ALGO:
                    dap_string_append_printf(a_str_out, "  codename: %s\n", l_emission->data.type_algo.codename);
                    break;
                case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ATOM_OWNER:
                    dap_string_append_printf(a_str_out, " value_start: %.0Lf(%"DAP_UINT64_FORMAT_U"), codename: %s\n",
                        dap_chain_datoshi_to_coins(l_emission->data.type_atom_owner.value_start),
                        l_emission->data.type_atom_owner.value_start,
                        l_emission->data.type_atom_owner.value_change_algo_codename
                    );
                break;
                case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_SMART_CONTRACT: {
                    char l_time_str[70];
                    char *l_addr = dap_chain_addr_to_str(&l_emission->data.type_presale.addr);
                    // get time of create datum
                    if(dap_time_to_str_rfc822(l_time_str, 71, l_emission->data.type_presale.lock_time) < 1)
                            l_time_str[0] = '\0';
                    dap_string_append_printf(a_str_out, "  flags: 0x%x, lock_time: %s\n", l_emission->data.type_presale.flags, l_time_str);
                    dap_string_append_printf(a_str_out, "  addr: %s\n", l_addr);
                    DAP_DELETE(l_addr);
                }
                break;
            }
            DAP_DELETE(l_emission);
        } break;
        case DAP_CHAIN_DATUM_TX: {
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)a_datum->data;
            dap_chain_datum_dump_tx(l_tx, NULL, a_str_out, a_hash_out_type, &l_datum_hash);
        } break;
    }
    DAP_DELETE(l_hash_str);
}
