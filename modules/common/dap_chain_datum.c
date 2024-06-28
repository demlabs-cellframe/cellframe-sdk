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
   dap_chain_datum_t *l_datum = NULL;
   DAP_NEW_Z_SIZE_RET_VAL(l_datum, dap_chain_datum_t, sizeof(l_datum->header) + a_data_size, NULL, NULL);
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

void dap_chain_datum_token_dump_tsd(dap_string_t *a_str_out, dap_chain_datum_token_t *a_token, size_t a_token_size, const char *a_hash_out_type)
{
    dap_tsd_t *l_tsd = dap_chain_datum_token_tsd_get(a_token, a_token_size);
    if (l_tsd == NULL) {
        dap_string_append_printf(a_str_out,"<CORRUPTED TSD SECTION>\n");
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
    size_t l_tsd_size = 0;
    for (size_t l_offset = 0; l_offset < l_tsd_total_size; l_offset += l_tsd_size) {
        l_tsd = (dap_tsd_t *) (((byte_t*)l_tsd) + l_tsd_size);
        l_tsd_size = l_tsd ? dap_tsd_size(l_tsd) : 0;
        if (l_tsd_size == 0) {
            log_it(L_ERROR,"Wrong zero TSD size, exiting dap_chain_datum_token_dump_tsd()");
            return;
        } else if (l_tsd_size+l_offset > l_tsd_total_size) {
            log_it(L_WARNING, "<CORRUPTED TSD> too big size %u when left maximum %zu",
                   l_tsd->size, l_tsd_total_size - l_offset);
            return;
        }
        switch(l_tsd->type) {
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_SET_FLAGS: {
            dap_string_append_printf(a_str_out,"flags_set: ");
            uint16_t l_t = 0;
            dap_chain_datum_token_flags_dump(a_str_out, _dap_tsd_get_scalar(l_tsd, &l_t));
            continue;
        }
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS: {
            dap_string_append_printf(a_str_out,"flags_unset: ");
            uint16_t l_t = 0;
            dap_chain_datum_token_flags_dump(a_str_out, _dap_tsd_get_scalar(l_tsd, &l_t));
            continue;
        }
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY: {     // 256
            uint256_t l_t = uint256_0;
            dap_string_append_printf( a_str_out, "total_supply: %s\n",
                                     dap_uint256_to_char(_dap_tsd_get_scalar(l_tsd, &l_t), NULL) );
            continue;
        }
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY_OLD: { // 128
            uint128_t l_t = uint128_0;
            dap_string_append_printf( a_str_out, "total_supply: %s\n",
                                     dap_uint256_to_char(GET_256_FROM_128(_dap_tsd_get_scalar(l_tsd, &l_t)), NULL) );
            continue;
        }
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID: {
            uint16_t l_t = 0;
            dap_string_append_printf(a_str_out,"total_signs_valid: %u\n", _dap_tsd_get_scalar(l_tsd, &l_t));
            continue;
        }
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_ADD:
            if(l_tsd->size >= sizeof(dap_pkey_t)) {
                const char *l_hash_str;
                dap_pkey_t *l_pkey = (dap_pkey_t*)l_tsd->data;
                dap_hash_fast_t l_hf = { };
                if (!dap_pkey_get_hash(l_pkey, &l_hf)) {
                    dap_string_append_printf(a_str_out,"total_pkeys_add: <WRONG CALCULATION FINGERPRINT>\n");
                } else {
                    if (!dap_strcmp(a_hash_out_type, "hex") || !dap_strcmp(a_hash_out_type, "content_hash"))
                        l_hash_str = dap_chain_hash_fast_to_str_static(&l_hf);
                    else
                        l_hash_str = dap_enc_base58_encode_hash_to_str_static(&l_hf);
                    dap_string_append_printf(a_str_out, "total_pkeys_add: %s\n", l_hash_str);
                }
            } else
                    dap_string_append_printf(a_str_out,"total_pkeys_add: <WRONG SIZE %u>\n", l_tsd->size);
            continue;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_REMOVE:
                if(l_tsd->size == sizeof(dap_chain_hash_fast_t) ){
                    const char *l_hash_str = (!dap_strcmp(a_hash_out_type,"hex")|| !dap_strcmp(a_hash_out_type, "content_hash"))
                            ? dap_chain_hash_fast_to_str_static((dap_chain_hash_fast_t*) l_tsd->data)
                            : dap_enc_base58_encode_hash_to_str_static((dap_chain_hash_fast_t*) l_tsd->data);
                    dap_string_append_printf(a_str_out,"total_pkeys_remove: %s\n", l_hash_str);
                } else
                    dap_string_append_printf(a_str_out,"total_pkeys_remove: <WRONG SIZE %u>\n", l_tsd->size);
            continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK: {
                dap_chain_datum_token_tsd_delegate_from_stake_lock_t *l_tsd_section = _dap_tsd_get_object(l_tsd, dap_chain_datum_token_tsd_delegate_from_stake_lock_t);
                const char *l_balance, *l_tmp = dap_uint256_to_char(l_tsd_section->emission_rate, &l_balance);
                dap_string_append_printf(a_str_out, "ticker_token_from: %s\nemission_rate: %s\n",
                                         l_tsd_section->ticker_token_from, l_balance);
            }continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD  :
                dap_string_append_printf(a_str_out,"datum_type_allowed_add: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_REMOVE  :
                dap_string_append_printf(a_str_out,"datum_type_allowed_remove: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_ADD  :
                dap_string_append_printf(a_str_out,"datum_type_blocked_add: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_REMOVE:
                dap_string_append_printf(a_str_out,"datum_type_blocked_remove: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD:
                dap_string_append_printf(a_str_out,"tx_sender_allowed_add: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_REMOVE:
                dap_string_append_printf(a_str_out,"tx_sender_allowed_remove: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD:
                dap_string_append_printf(a_str_out,"tx_sender_blocked_add: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_REMOVE:
                dap_string_append_printf(a_str_out,"tx_sender_blocked_remove: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD:
                dap_string_append_printf(a_str_out,"tx_receiver_allowed_add: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_REMOVE:
                dap_string_append_printf(a_str_out,"tx_receiver_allowed: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD:
                dap_string_append_printf(a_str_out, "tx_receiver_blocked_add: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_REMOVE:
                dap_string_append_printf(a_str_out, "tx_receiver_blocked_remove: %s\n",
                                         dap_tsd_get_string_const(l_tsd) );
            continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TOKEN_DESCRIPTION:
                dap_string_append_printf(a_str_out, "description: '%s'\n", l_tsd->data);
                continue;
            default: dap_string_append_printf(a_str_out, "<0x%04hX>: <size %u>\n", l_tsd->type, l_tsd->size);
        }
    }
}

void dap_datum_token_dump_tsd_to_json(json_object * json_obj_out, dap_chain_datum_token_t *a_token, size_t a_token_size, const char *a_hash_out_type)
{
    dap_tsd_t *l_tsd = dap_chain_datum_token_tsd_get(a_token, a_token_size);
    if (l_tsd == NULL) {
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
    size_t l_tsd_size = 0;
    for (size_t l_offset = 0; l_offset < l_tsd_total_size; l_offset += l_tsd_size) {
        l_tsd = (dap_tsd_t *) (((byte_t*)l_tsd) + l_tsd_size);
        l_tsd_size = l_tsd ? dap_tsd_size(l_tsd) : 0;
        if (l_tsd_size == 0) {
            log_it(L_ERROR,"Wrong zero TSD size, exiting s_datum_token_dump_tsd()");
            return;
        } else if (l_tsd_size+l_offset > l_tsd_total_size) {
            log_it(L_WARNING, "<CORRUPTED TSD> too big size %u when left maximum %zu",
                   l_tsd->size, l_tsd_total_size - l_offset);
            return;
        }
        switch(l_tsd->type) {
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_SET_FLAGS: {
            uint16_t l_t = 0;
            dap_chain_datum_token_flags_dump_to_json(json_obj_out,_dap_tsd_get_scalar(l_tsd, &l_t));
            json_object_object_add(json_obj_out, "flags_set", json_object_new_string("empty"));
            continue;
        }
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS: {
            uint16_t l_t = 0;
            dap_chain_datum_token_flags_dump_to_json(json_obj_out,_dap_tsd_get_scalar(l_tsd, &l_t));
            json_object_object_add(json_obj_out, "flags_unset", json_object_new_string("empty"));
            continue;
        }
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY: {     // 256
            uint256_t l_t = uint256_0;
            char *l_balance = dap_chain_balance_print(_dap_tsd_get_scalar(l_tsd, &l_t));
            json_object_object_add(json_obj_out, "total_supply", json_object_new_string(l_balance));
            DAP_DELETE(l_balance);
            continue;
        }
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY_OLD: { // 128
            uint128_t l_t = uint128_0;
            char *l_balance = dap_chain_balance_print(GET_256_FROM_128(_dap_tsd_get_scalar(l_tsd, &l_t)));
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
            json_object_object_add(json_obj_out, "ticker_token_from", json_object_new_string((char *)l_tsd_section->ticker_token_from));
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
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD:
            json_object_object_add(json_obj_out, "tx_sender_allowed_add", json_object_new_string(dap_tsd_get_string_const(l_tsd)));
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_REMOVE:
            json_object_object_add(json_obj_out, "tx_sender_allowed_remove", json_object_new_string(dap_tsd_get_string_const(l_tsd)));
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD:
            json_object_object_add(json_obj_out, "tx_sender_blocked_add", json_object_new_string(dap_tsd_get_string_const(l_tsd)));
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_REMOVE:
            json_object_object_add(json_obj_out, "tx_sender_blocked_remove", json_object_new_string(dap_tsd_get_string_const(l_tsd)));
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD:
            json_object_object_add(json_obj_out, "tx_receiver_allowed_add", json_object_new_string(dap_tsd_get_string_const(l_tsd)));
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_REMOVE:
            json_object_object_add(json_obj_out, "tx_receiver_allowed", json_object_new_string(dap_tsd_get_string_const(l_tsd)));
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD:
            json_object_object_add(json_obj_out, "tx_receiver_blocked_add", json_object_new_string(dap_tsd_get_string_const(l_tsd)));
            continue;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_REMOVE:
            json_object_object_add(json_obj_out, "tx_receiver_blocked_remove", json_object_new_string(dap_tsd_get_string_const(l_tsd)));
            continue;
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
bool dap_chain_datum_dump_tx(dap_chain_datum_tx_t *a_datum,
                             const char *a_ticker,
                             dap_string_t *a_str_out,
                             const char *a_hash_out_type,
                             dap_hash_fast_t *a_tx_hash,
                             dap_chain_net_id_t a_net_id)
{
    bool l_is_first = false;
    dap_chain_tx_in_t *l_in_item = (dap_chain_tx_in_t *)dap_chain_datum_tx_item_get(a_datum, NULL, TX_ITEM_TYPE_IN, NULL);
    if (l_in_item && dap_hash_fast_is_blank(&l_in_item->header.tx_prev_hash))
        l_is_first = true;
    char l_tmp_buf[DAP_TIME_STR_SIZE];
    const char *l_hash_str = dap_strcmp(a_hash_out_type, "hex")
            ? dap_enc_base58_encode_hash_to_str_static(a_tx_hash)
            : dap_chain_hash_fast_to_str_static(a_tx_hash);
    dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, a_datum->header.ts_created);
    dap_string_append_printf(a_str_out, "transaction:%s hash %s\n TS Created: %s%s%s\n Items:\n",
                             l_is_first ? " (emit)" : "", l_hash_str, l_tmp_buf,
                             a_ticker ? " Token ticker: " : "", a_ticker ? a_ticker : "");
    uint32_t l_tx_items_count = 0;
    uint32_t l_tx_items_size = a_datum->header.tx_items_size;
    dap_hash_fast_t *l_hash_tmp = NULL;
    while (l_tx_items_count < l_tx_items_size) {
        uint8_t *item = a_datum->tx_items + l_tx_items_count;
        size_t l_item_tx_size = dap_chain_datum_item_tx_get_size(item);
        switch(dap_chain_datum_tx_item_get_type(item)){
        case TX_ITEM_TYPE_IN:
            l_hash_tmp = &((dap_chain_tx_in_t*)item)->header.tx_prev_hash;
            if (dap_hash_fast_is_blank(l_hash_tmp)) {
                l_hash_str = "BLANK";
            } else {
                l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                        ? dap_enc_base58_encode_hash_to_str_static(l_hash_tmp)
                        : dap_chain_hash_fast_to_str_static(l_hash_tmp);
            }
            dap_string_append_printf(a_str_out, "\t IN:\nTx_prev_hash: %s\n"
                                                "\t\t Tx_out_prev_idx: %u\n",
                                        l_hash_str,
                                        ((dap_chain_tx_in_t*)item)->header.tx_out_prev_idx);
            break;
        case TX_ITEM_TYPE_OUT_OLD: {
            const char *l_value_str = dap_uint256_to_char(
                dap_chain_uint256_from(((dap_chain_tx_out_old_t*)item)->header.value), NULL );
            dap_string_append_printf(a_str_out, "\t OUT OLD (64):\n"
                                                "\t\t Value: %s (%"DAP_UINT64_FORMAT_U")\n"
                                                "\t\t Address: %s\n",
                                        l_value_str,
                                        ((dap_chain_tx_out_old_t*)item)->header.value,
                                        dap_chain_addr_to_str(&((dap_chain_tx_out_old_t*)item)->addr));
        } break;
        case TX_ITEM_TYPE_OUT: { // 256
            const char *l_coins_str,
                    *l_value_str = dap_uint256_to_char(((dap_chain_tx_out_t*)item)->header.value, &l_coins_str),
                    *l_addr_str = dap_chain_addr_to_str(&((dap_chain_tx_out_t*)item)->addr);
            dap_string_append_printf(a_str_out, "\t OUT:\n"
                                                "\t\t Value: %s (%s)\n"
                                                "\t\t Address: %s\n",
                                        l_coins_str,
                                        l_value_str,
                                        l_addr_str);
        } break;
        case TX_ITEM_TYPE_IN_EMS: {
            l_hash_tmp = &((dap_chain_tx_in_ems_t*)item)->header.token_emission_hash;
            l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str_static(l_hash_tmp)
                    : dap_chain_hash_fast_to_str_static(l_hash_tmp);
            dap_string_append_printf(a_str_out, "\t IN_EMS:\n"
                                                "\t\t ticker: %s \n"
                                                "\t\t token_emission_hash: %s\n"
                                                "\t\t token_emission_chain_id: 0x%016"DAP_UINT64_FORMAT_x"\n",
                                                ((dap_chain_tx_in_ems_t*)item)->header.ticker,
                                                l_hash_str,
                                                ((dap_chain_tx_in_ems_t*)item)->header.token_emission_chain_id.uint64);
        } break;
            /*
        case TX_ITEM_TYPE_IN_EMS_EXT: {
            l_hash_tmp = &((dap_chain_tx_in_ems_ext_t*)item)->header.ext_tx_hash;
            l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str(l_hash_tmp)
                    : dap_chain_hash_fast_to_str_new(l_hash_tmp);
            dap_string_append_printf(a_str_out, "\t IN_EMS EXT:\n"
                                         "\t\t Version: %u\n"
                                         "\t\t Ticker: %s\n"
                                         "\t\t Ext chain id: 0x%016"DAP_UINT64_FORMAT_x"\n"
                                         "\t\t Ext net id: 0x%016"DAP_UINT64_FORMAT_x"\n"
                                         "\t\t Ext tx hash: %s\n"
                                         "\t\t Ext tx out idx: %u\n",
                                     ((dap_chain_tx_in_ems_ext_t*)item)->header.version,
                                     ((dap_chain_tx_in_ems_ext_t*)item)->header.ticker,
                                     ((dap_chain_tx_in_ems_ext_t*)item)->header.ext_chain_id.uint64,
                                     ((dap_chain_tx_in_ems_ext_t*)item)->header.ext_net_id.uint64,
                                     l_hash_str,
                                     ((dap_chain_tx_in_ems_ext_t*)item)->header.ext_tx_out_idx);
            DAP_DELETE(l_hash_str);
        } break; */

        case TX_ITEM_TYPE_IN_REWARD: {
            l_hash_tmp = &((dap_chain_tx_in_reward_t *)item)->block_hash;
            l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str_static(l_hash_tmp)
                    : dap_chain_hash_fast_to_str_static(l_hash_tmp);
            dap_string_append_printf(a_str_out, "\t IN_REWARD:\n"
                                                "\t\t block_hash: %s\n",
                                                l_hash_str);
        } break;

        case TX_ITEM_TYPE_SIG: {
            dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t*)item);
            dap_sign_get_information(l_sign, a_str_out, a_hash_out_type);
            dap_chain_addr_t l_sender_addr;
            dap_chain_addr_fill_from_sign(&l_sender_addr, l_sign, a_net_id);
            dap_string_append_printf(a_str_out, "\tSender addr: %s\n", dap_chain_addr_to_str(&l_sender_addr));
        } break;
        case TX_ITEM_TYPE_RECEIPT: {
            const char *l_coins_str, *l_value_str = dap_uint256_to_char(((dap_chain_datum_tx_receipt_t*)item)->receipt_info.value_datoshi, &l_coins_str);
            dap_string_append_printf(a_str_out, "\t Receipt:\n"
                                                "\t\t size: %"DAP_UINT64_FORMAT_U"\n"
                                                "\t\t ext size: %"DAP_UINT64_FORMAT_U"\n"
                                                "\t\t Info:"
                                                "\t\t\t units: 0x%016"DAP_UINT64_FORMAT_x"\n"
                                                "\t\t\t uid: 0x%016"DAP_UINT64_FORMAT_x"\n"
                                                "\t\t\t units type: %s \n"
                                                "\t\t\t value: %s (%s)\n",
                                     ((dap_chain_datum_tx_receipt_t*)item)->size,
                                     ((dap_chain_datum_tx_receipt_t*)item)->exts_size,
                                     ((dap_chain_datum_tx_receipt_t*)item)->receipt_info.units,
                                     ((dap_chain_datum_tx_receipt_t*)item)->receipt_info.srv_uid.uint64,
                                     dap_chain_srv_unit_enum_to_str(((dap_chain_datum_tx_receipt_t*)item)->receipt_info.units_type.enm),
                                     l_coins_str,
                                     l_value_str);
            dap_string_append_printf(a_str_out, "Exts:\n");                         
            switch ( ((dap_chain_datum_tx_receipt_t*)item)->exts_size ) {
            case (sizeof(dap_sign_t) * 2): {
                dap_sign_t *l_client = DAP_CAST_PTR( dap_sign_t, ((dap_chain_datum_tx_receipt_t*)item)->exts_n_signs + sizeof(dap_sign_t) );
                dap_string_append_printf(a_str_out, "   Client:\n");
                dap_sign_get_information(l_client, a_str_out, a_hash_out_type);
            }
            case (sizeof(dap_sign_t)): {
                dap_sign_t *l_provider = DAP_CAST_PTR( dap_sign_t, ((dap_chain_datum_tx_receipt_t*)item)->exts_n_signs );
                dap_string_append_printf(a_str_out, "   Provider:\n");
                dap_sign_get_information(l_provider, a_str_out, a_hash_out_type);
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
                                     dap_pkey_type_to_str(l_pkey->header.type),
                                     l_pkey->header.size,
                                     l_hash_str);
        } break;
        case TX_ITEM_TYPE_TSD: {
            dap_string_append_printf(a_str_out, "\t TSD data: \n"
                                                "\t\t type: %d\n"
                                                "\t\t size: %lu\n",
                                     ((dap_chain_tx_tsd_t*)item)->header.type,
                                     ((dap_chain_tx_tsd_t*)item)->header.size);
        } break;
        case TX_ITEM_TYPE_IN_COND:
            l_hash_tmp = &((dap_chain_tx_in_cond_t*)item)->header.tx_prev_hash;
            l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str_static(l_hash_tmp)
                    : dap_chain_hash_fast_to_str_static(l_hash_tmp);
            dap_string_append_printf(a_str_out, "\t IN COND:\n\t\tReceipt_idx: %u\n"
                                                "\t\t Tx_prev_hash: %s\n"
                                                "\t\t Tx_out_prev_idx: %u\n",
                                     ((dap_chain_tx_in_cond_t*)item)->header.receipt_idx,
                                     l_hash_str,
                                     ((dap_chain_tx_in_cond_t*)item)->header.tx_out_prev_idx);
            break;
        case TX_ITEM_TYPE_OUT_COND: {
            const char *l_coins_str, *l_value_str = dap_uint256_to_char(((dap_chain_tx_out_cond_t*)item)->header.value, &l_coins_str);
            dap_time_t l_ts_exp = ((dap_chain_tx_out_cond_t*)item)->header.ts_expires;
            dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_ts_exp);
            dap_string_append_printf(a_str_out, "\t OUT COND:\n"
                                                "\t Header:\n"
                                                "\t\t ts_expires: %s"
                                                "\t\t value: %s (%s)\n"
                                                "\t\t subtype: %s\n"
                                                "\t\t uid: 0x%016"DAP_UINT64_FORMAT_x"\n",
                                     l_ts_exp ? l_tmp_buf : "never\n", l_coins_str, l_value_str,
                                     dap_chain_tx_out_cond_subtype_to_str(((dap_chain_tx_out_cond_t*)item)->header.subtype),
                                     ((dap_chain_tx_out_cond_t*)item)->header.srv_uid.uint64);
            switch (((dap_chain_tx_out_cond_t*)item)->header.subtype) {
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY: {
                    const char *l_coins_str, *l_value_str =
                        dap_uint256_to_char( ((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.unit_price_max_datoshi, &l_coins_str );
                    l_hash_tmp = &((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.pkey_hash;
                    l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                            ? dap_enc_base58_encode_hash_to_str_static(l_hash_tmp)
                            : dap_chain_hash_fast_to_str_static(l_hash_tmp);
                    dap_string_append_printf(a_str_out, "\t\t\t unit: 0x%08x\n"
                                                        "\t\t\t pkey: %s\n"
                                                        "\t\t\t max price: %s (%s)\n",
                                             ((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.unit.uint32,
                                             l_hash_str,
                                             l_coins_str,
                                             l_value_str);
                } break;
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE: {
                    dap_chain_node_addr_t *l_signer_node_addr = &((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake_pos_delegate.signer_node_addr;
                    dap_chain_addr_t *l_signing_addr = &((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake_pos_delegate.signing_addr;
                    l_hash_tmp = &l_signing_addr->data.hash_fast;
                    l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                            ? dap_enc_base58_encode_hash_to_str_static(l_hash_tmp)
                            : dap_chain_hash_fast_to_str_static(l_hash_tmp);
                    dap_string_append_printf(a_str_out, "\t\t\t signing_addr: %s\n"
                                                        "\t\t\t with pkey hash %s\n"
                                                        "\t\t\t signer_node_addr: "NODE_ADDR_FP_STR"\n",
                                                        dap_chain_addr_to_str(l_signing_addr),
                                                        l_hash_str,
                                                        NODE_ADDR_FP_ARGS(l_signer_node_addr));
                } break;
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE: {
                    const char *l_rate_str, *l_tmp_str =
                        dap_uint256_to_char( (((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.rate), &l_rate_str );
                    dap_string_append_printf(a_str_out, "\t\t\t net id: 0x%016"DAP_UINT64_FORMAT_x"\n"
                                                        "\t\t\t buy_token: %s\n"
                                                        "\t\t\t rate: %s\n",
                                             ((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.buy_net_id.uint64,
                                             ((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.buy_token,
                                             l_rate_str);
                } break;
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK: {
                    dap_time_t l_ts_unlock = ((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake_lock.time_unlock;
                    dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_ts_unlock);
                    dap_string_append_printf(a_str_out, "\t\t\t time_unlock %s\n", l_tmp_buf);
                } break;
                default: break;
            }
        } break;
        case TX_ITEM_TYPE_OUT_EXT: {
            const char *l_coins_str, *l_value_str = dap_uint256_to_char( ((dap_chain_tx_out_ext_t*)item)->header.value, &l_coins_str);
            dap_string_append_printf(a_str_out, "\t OUT EXT:\n"
                                                "\t\t Addr: %s\n"
                                                "\t\t Token: %s\n"
                                                "\t\t Value: %s (%s)\n",
                                     dap_chain_addr_to_str(&((dap_chain_tx_out_ext_t*)item)->addr),
                                     ((dap_chain_tx_out_ext_t*)item)->token,
                                     l_coins_str,
                                     l_value_str);
        } break;
        case TX_ITEM_TYPE_VOTING:{
            int l_tsd_size = 0;
            dap_chain_tx_tsd_t *l_item = (dap_chain_tx_tsd_t *)dap_chain_datum_tx_item_get(a_datum, 0, TX_ITEM_TYPE_TSD, &l_tsd_size);
            if (!l_item || !l_tsd_size)
                    break;
            dap_chain_datum_tx_voting_params_t *l_voting_params = dap_chain_voting_parse_tsd(a_datum);
            dap_string_append_printf(a_str_out, "\t VOTING:\n\tVoting question: %s\n\t Answer options:\n", l_voting_params->voting_question);
            dap_list_t *l_temp = l_voting_params->answers_list;
            uint8_t l_index = 0;
            while (l_temp){
                    dap_string_append_printf(a_str_out, "\t\t %i) %s\n", l_index, (char*)l_temp->data);
                    l_index++;
                    l_temp = l_temp->next;
            }

            if (l_voting_params->voting_expire) {
                dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_voting_params->voting_expire);
                dap_string_append_printf(a_str_out, "\t Voting expire: %s\n", l_tmp_buf);
            }
            if (l_voting_params->votes_max_count)
                    dap_string_append_printf(a_str_out, "\t Votes max count: %"DAP_UINT64_FORMAT_U"\n", l_voting_params->votes_max_count);
            dap_string_append_printf(a_str_out, "\t Changing vote is %s available.\n", l_voting_params->vote_changing_allowed ? "" : "not");
            dap_string_append_printf(a_str_out, "\t A delegated key is%s required to participate in voting. \n",
                                     l_voting_params->delegate_key_required ? "" : " not");

            dap_list_free_full(l_voting_params->answers_list, NULL);
            DAP_DELETE(l_voting_params->voting_question);
            DAP_DELETE(l_voting_params);
        } break;
        case TX_ITEM_TYPE_VOTE:{
            dap_chain_tx_vote_t *l_vote_item = (dap_chain_tx_vote_t *)item;
            const char *l_hash_str = dap_chain_hash_fast_to_str_static(&l_vote_item->voting_hash);
            dap_string_append_printf(a_str_out, "\t VOTE: \n"
                                                "\t Voting hash: %s\n"
                                                "\t Vote answer idx: %"DAP_UINT64_FORMAT_U"\n", l_hash_str, l_vote_item->answer_idx);
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
bool dap_chain_datum_dump_tx_json(dap_chain_datum_tx_t *a_datum,
                             const char *a_ticker,
                             json_object* json_obj_out,
                             const char *a_hash_out_type,
                             dap_hash_fast_t *a_tx_hash,
                             dap_chain_net_id_t a_net_id)
{
    bool l_is_first = false;
    dap_chain_tx_in_t *l_in_item = (dap_chain_tx_in_t *)dap_chain_datum_tx_item_get(a_datum, NULL, TX_ITEM_TYPE_IN, NULL);
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
    json_object_object_add(json_obj_out, "TS Created", json_object_new_string(l_tmp_buf));
    json_object_object_add(json_obj_out, "Token ticker", a_ticker ? json_object_new_string(a_ticker) : json_object_new_string(""));
    //json_object_array_add(json_arr_items, json_obj_tx);
    
    uint32_t l_tx_items_count = 0;
    uint32_t l_tx_items_size = a_datum->header.tx_items_size;
    dap_hash_fast_t *l_hash_tmp = NULL;
    while (l_tx_items_count < l_tx_items_size) {
        json_object* json_obj_item = json_object_new_object();
        uint8_t *item = a_datum->tx_items + l_tx_items_count;
        size_t l_item_tx_size = dap_chain_datum_item_tx_get_size(item);
        switch(dap_chain_datum_tx_item_get_type(item)){
        case TX_ITEM_TYPE_IN:
            l_hash_tmp = &((dap_chain_tx_in_t*)item)->header.tx_prev_hash;
            if (dap_hash_fast_is_blank(l_hash_tmp)) {
                l_hash_str = "BLANK";
            } else {
                l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                        ? dap_enc_base58_encode_hash_to_str_static(l_hash_tmp)
                        : dap_chain_hash_fast_to_str_static(l_hash_tmp);
            }
            json_object_object_add(json_obj_item,"item type", json_object_new_string("IN"));
            json_object_object_add(json_obj_item,"Tx prev hash", json_object_new_string(l_hash_str));
            json_object_object_add(json_obj_item,"Tx out prev idx", json_object_new_uint64(((dap_chain_tx_in_t*)item)->header.tx_out_prev_idx));
            break;
        case TX_ITEM_TYPE_OUT_OLD: {
            const char *l_value_str = dap_uint256_to_char(
                dap_chain_uint256_from(((dap_chain_tx_out_old_t*)item)->header.value), NULL );
            json_object_object_add(json_obj_item,"item type", json_object_new_string("OUT OLD"));
            json_object_object_add(json_obj_item,"Value", json_object_new_uint64(((dap_chain_tx_out_old_t*)item)->header.value));
            json_object_object_add(json_obj_item,"Address", json_object_new_string(dap_chain_addr_to_str(&((dap_chain_tx_out_old_t*)item)->addr)));
        } break;
        case TX_ITEM_TYPE_OUT: { // 256
            const char *l_coins_str,
                    *l_value_str = dap_uint256_to_char(((dap_chain_tx_out_t*)item)->header.value, &l_coins_str),
                    *l_addr_str = dap_chain_addr_to_str(&((dap_chain_tx_out_t*)item)->addr);
            json_object_object_add(json_obj_item,"item type", json_object_new_string("OUT"));
            json_object_object_add(json_obj_item,"Coins", json_object_new_string(l_coins_str));
            json_object_object_add(json_obj_item,"Value", json_object_new_string(l_value_str));
            json_object_object_add(json_obj_item,"Address", json_object_new_string(l_addr_str));            
        } break;
        case TX_ITEM_TYPE_IN_EMS: {
            char l_tmp_buff[70]={0};
            l_hash_tmp = &((dap_chain_tx_in_ems_t*)item)->header.token_emission_hash;
            l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str_static(l_hash_tmp)
                    : dap_chain_hash_fast_to_str_static(l_hash_tmp);
            json_object_object_add(json_obj_item,"item type", json_object_new_string("IN_EMS"));
            json_object_object_add(json_obj_item,"ticker", json_object_new_string(((dap_chain_tx_in_ems_t*)item)->header.ticker));
            json_object_object_add(json_obj_item,"token_emission_hash", json_object_new_string(l_hash_str));
            sprintf(l_tmp_buff,"0x%016"DAP_UINT64_FORMAT_x"",((dap_chain_tx_in_ems_t*)item)->header.token_emission_chain_id.uint64);
            json_object_object_add(json_obj_item,"token_emission_chain_id", json_object_new_string(l_tmp_buff));
        } break;
            /*
        case TX_ITEM_TYPE_IN_EMS_EXT: {
            l_hash_tmp = &((dap_chain_tx_in_ems_ext_t*)item)->header.ext_tx_hash;
            l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str(l_hash_tmp)
                    : dap_chain_hash_fast_to_str_new(l_hash_tmp);
            dap_string_append_printf(a_str_out, "\t IN_EMS EXT:\n"
                                         "\t\t Version: %u\n"
                                         "\t\t Ticker: %s\n"
                                         "\t\t Ext chain id: 0x%016"DAP_UINT64_FORMAT_x"\n"
                                         "\t\t Ext net id: 0x%016"DAP_UINT64_FORMAT_x"\n"
                                         "\t\t Ext tx hash: %s\n"
                                         "\t\t Ext tx out idx: %u\n",
                                     ((dap_chain_tx_in_ems_ext_t*)item)->header.version,
                                     ((dap_chain_tx_in_ems_ext_t*)item)->header.ticker,
                                     ((dap_chain_tx_in_ems_ext_t*)item)->header.ext_chain_id.uint64,
                                     ((dap_chain_tx_in_ems_ext_t*)item)->header.ext_net_id.uint64,
                                     l_hash_str,
                                     ((dap_chain_tx_in_ems_ext_t*)item)->header.ext_tx_out_idx);
            DAP_DELETE(l_hash_str);
        } break; */

        case TX_ITEM_TYPE_IN_REWARD: {
            l_hash_tmp = &((dap_chain_tx_in_reward_t *)item)->block_hash;
            l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str_static(l_hash_tmp)
                    : dap_chain_hash_fast_to_str_static(l_hash_tmp);
            json_object_object_add(json_obj_item,"item type", json_object_new_string("IN_REWARD"));
            json_object_object_add(json_obj_item,"block_hash", json_object_new_string(l_hash_str));
        } break;

        case TX_ITEM_TYPE_SIG: {
            dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t*)item);
            json_object_object_add(json_obj_item,"item type", json_object_new_string("SIG"));
            dap_sign_get_information_json(l_sign, json_obj_item, a_hash_out_type);
            dap_chain_addr_t l_sender_addr;
            dap_chain_addr_fill_from_sign(&l_sender_addr, l_sign, a_net_id);
            json_object_object_add(json_obj_item,"Sender addr", json_object_new_string(dap_chain_addr_to_str(&l_sender_addr)));            
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
                dap_sign_t *l_client = DAP_CAST_PTR( dap_sign_t, ((dap_chain_datum_tx_receipt_t*)item)->exts_n_signs + sizeof(dap_sign_t) );
                json_object_object_add(json_obj_item,"Client", json_object_new_string(""));
                dap_sign_get_information_json(l_client, json_obj_item, a_hash_out_type);                
            }
            case (sizeof(dap_sign_t)): {
                dap_sign_t *l_provider = DAP_CAST_PTR( dap_sign_t, ((dap_chain_datum_tx_receipt_t*)item)->exts_n_signs );
                json_object_object_add(json_obj_item,"Provider", json_object_new_string(""));
                dap_sign_get_information_json(l_provider,json_obj_item, a_hash_out_type);
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
            l_hash_tmp = &((dap_chain_tx_in_cond_t*)item)->header.tx_prev_hash;
            l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str_static(l_hash_tmp)
                    : dap_chain_hash_fast_to_str_static(l_hash_tmp);
            json_object_object_add(json_obj_item,"Receipt_idx", json_object_new_uint64(((dap_chain_tx_in_cond_t*)item)->header.receipt_idx));
            json_object_object_add(json_obj_item,"Tx_prev_hash", json_object_new_string(l_hash_str));
            json_object_object_add(json_obj_item,"Tx_out_prev_idx", json_object_new_uint64(((dap_chain_tx_in_cond_t*)item)->header.tx_out_prev_idx));
            break;
        case TX_ITEM_TYPE_OUT_COND: {
            char l_tmp_buff[70]={0};
            json_object_object_add(json_obj_item,"item type", json_object_new_string("OUT COND"));
            const char *l_coins_str, *l_value_str = dap_uint256_to_char(((dap_chain_tx_out_cond_t*)item)->header.value, &l_coins_str);
            dap_time_t l_ts_exp = ((dap_chain_tx_out_cond_t*)item)->header.ts_expires;
            dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_ts_exp);
            json_object_object_add(json_obj_item,"Header", json_object_new_string(""));
            json_object_object_add(json_obj_item,"ts_expires", l_ts_exp ? json_object_new_string(l_tmp_buf) : json_object_new_string("never"));
            json_object_object_add(json_obj_item,"coins", json_object_new_string(l_coins_str));
            json_object_object_add(json_obj_item,"value", json_object_new_string(l_value_str));
            json_object_object_add(json_obj_item,"subtype", json_object_new_string(dap_chain_tx_out_cond_subtype_to_str(((dap_chain_tx_out_cond_t*)item)->header.subtype)));
            sprintf(l_tmp_buff,"0x%016"DAP_UINT64_FORMAT_x"",((dap_chain_tx_out_cond_t*)item)->header.srv_uid.uint64);
            json_object_object_add(json_obj_item,"uid", json_object_new_string(l_tmp_buff));
            switch (((dap_chain_tx_out_cond_t*)item)->header.subtype) {
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY: {
                    const char *l_coins_str, *l_value_str =
                        dap_uint256_to_char( ((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.unit_price_max_datoshi, &l_coins_str );
                    l_hash_tmp = &((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.pkey_hash;
                    l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                            ? dap_enc_base58_encode_hash_to_str_static(l_hash_tmp)
                            : dap_chain_hash_fast_to_str_static(l_hash_tmp);
                    sprintf(l_tmp_buff,"0x%08x",((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.unit.uint32);
                    json_object_object_add(json_obj_item,"unit", json_object_new_string(l_tmp_buff));
                    json_object_object_add(json_obj_item,"pkey", json_object_new_string(l_hash_str));
                    json_object_object_add(json_obj_item,"max price(coins)", json_object_new_string(l_coins_str));
                    json_object_object_add(json_obj_item,"max price(value)", json_object_new_string(l_value_str));

                } break;
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE: {
                    dap_chain_node_addr_t *l_signer_node_addr = &((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake_pos_delegate.signer_node_addr;
                    dap_chain_addr_t *l_signing_addr = &((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake_pos_delegate.signing_addr;
                    l_hash_tmp = &l_signing_addr->data.hash_fast;
                    l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                            ? dap_enc_base58_encode_hash_to_str_static(l_hash_tmp)
                            : dap_chain_hash_fast_to_str_static(l_hash_tmp);
                    json_object_object_add(json_obj_item,"signing_addr", json_object_new_string(dap_chain_addr_to_str(l_signing_addr)));
                    json_object_object_add(json_obj_item,"with pkey hash", json_object_new_string(l_hash_str));                    
                    sprintf(l_tmp_buff,""NODE_ADDR_FP_STR"",NODE_ADDR_FP_ARGS(l_signer_node_addr));
                    json_object_object_add(json_obj_item,"signer_node_addr", json_object_new_string(l_tmp_buff));
                    
                } break;
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE: {
                    const char *l_rate_str, *l_tmp_str =
                        dap_uint256_to_char( (((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.rate), &l_rate_str );
                    sprintf(l_tmp_buff,"0x%016"DAP_UINT64_FORMAT_x"",((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.buy_net_id.uint64);
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
            json_object_object_add(json_obj_item,"Addr", json_object_new_string(dap_chain_addr_to_str(&((dap_chain_tx_out_ext_t*)item)->addr)));
            json_object_object_add(json_obj_item,"Token", json_object_new_string(((dap_chain_tx_out_ext_t*)item)->token));
            json_object_object_add(json_obj_item,"Coins", json_object_new_string(l_coins_str));
            json_object_object_add(json_obj_item,"Value", json_object_new_string(l_value_str));
            
        } break;
        case TX_ITEM_TYPE_VOTING:{
            int l_tsd_size = 0;
            dap_chain_tx_tsd_t *l_item = (dap_chain_tx_tsd_t *)dap_chain_datum_tx_item_get(a_datum, 0, TX_ITEM_TYPE_TSD, &l_tsd_size);
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
                json_object_object_add(json_obj_item,"Votes max count", json_object_new_string("A delegated key is required to participate in voting.")):
                json_object_object_add(json_obj_item,"Votes max count", json_object_new_string("A delegated key is not required to participate in voting."));                 

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
        l_tx_items_count += l_item_tx_size;
        // Freeze protection
        if(!l_item_tx_size)
        {
            break;
        }

    }
    json_object_object_add(json_obj_out, "ITEMS", json_arr_items);
    return true;
}

/**
 * @brief dap_chain_net_dump_datum
 * process datum verification process. Can be:
 * if DAP_CHAIN_DATUM_TX, called dap_ledger_tx_add_check
 * if DAP_CHAIN_DATUM_TOKEN_DECL, called dap_ledger_token_decl_add_check
 * if DAP_CHAIN_DATUM_TOKEN_EMISSION, called dap_ledger_token_emission_add_check
 * @param a_str_out
 * @param a_datum
 */
void dap_chain_datum_dump(dap_string_t *a_str_out, dap_chain_datum_t *a_datum, const char *a_hash_out_type, dap_chain_net_id_t a_net_id)
{
    if( a_datum == NULL){
        dap_string_append_printf(a_str_out,"==Datum is NULL\n");
        return;
    }
    dap_hash_fast_t l_datum_hash;
    dap_hash_fast(a_datum->data, a_datum->header.data_size, &l_datum_hash);
    const char *l_hash_str = dap_strcmp(a_hash_out_type, "hex")
            ? dap_enc_base58_encode_hash_to_str_static(&l_datum_hash)
            : dap_chain_hash_fast_to_str_static(&l_datum_hash);
    switch (a_datum->header.type_id) {
        case DAP_CHAIN_DATUM_TOKEN_DECL: {
            size_t l_token_size = a_datum->header.data_size;
            dap_chain_datum_token_t * l_token = dap_chain_datum_token_read(a_datum->data, &l_token_size);
            if(l_token_size < sizeof(dap_chain_datum_token_t)){
                dap_string_append_printf(a_str_out,"==Datum has incorrect size. Only %zu, while at least %zu is expected\n",
                                         l_token_size, sizeof(dap_chain_datum_token_t));
                DAP_DEL_Z(l_token);
                return;
            }
            dap_string_append_printf(a_str_out,"=== Datum Token Declaration ===\n");
            dap_string_append_printf(a_str_out, "hash: %s\n", l_hash_str);
            dap_string_append_printf(a_str_out, "ticker: %s\n", l_token->ticker);
            dap_string_append_printf(a_str_out, "size: %zd\n", l_token_size);
            dap_string_append_printf(a_str_out, "version: %d\n", l_token->version);
            switch (l_token->type) {
                case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL: {
                    dap_string_append(a_str_out,"type: DECL\n");
                    switch (l_token->subtype) {
                        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:{
                            dap_string_append(a_str_out,"subtype: PRIVATE\n");
                            dap_string_append_printf(a_str_out, "decimals: %d\n", l_token->header_private_decl.decimals);
                            dap_string_append_printf(a_str_out, "auth signs (valid/total) %u/%u\n", l_token->signs_valid, l_token->signs_total);
                            dap_string_append_printf(a_str_out, "total_supply: %s\n", dap_uint256_to_char(l_token->total_supply, NULL));
                            dap_string_append(a_str_out,"flags: ");
                            dap_chain_datum_token_flags_dump(a_str_out, l_token->header_private_update.flags);
                            dap_chain_datum_token_dump_tsd(a_str_out, l_token, l_token_size, a_hash_out_type);
                            size_t l_certs_field_size = l_token_size - sizeof(*l_token) - l_token->header_private_update.tsd_total_size;
                            dap_chain_datum_token_certs_dump(a_str_out, l_token->data_n_tsd + l_token->header_private_update.tsd_total_size,
                                                             l_certs_field_size, a_hash_out_type);
                        } break;
                        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE: {
                            dap_string_append(a_str_out, "subtype: CF20\n");
                            dap_string_append_printf(a_str_out, "decimals: %d\n", l_token->header_native_decl.decimals);
                            dap_string_append_printf(a_str_out, "auth signs (valid/total) %u/%u\n", l_token->signs_valid, l_token->signs_total);
                            dap_string_append_printf(a_str_out, "total_supply: %s\n", dap_uint256_to_char(l_token->total_supply, NULL));
                            dap_string_append(a_str_out, "flags: ");
                            dap_chain_datum_token_flags_dump(a_str_out, l_token->header_native_decl.flags);
                            dap_chain_datum_token_dump_tsd(a_str_out, l_token, l_token_size, a_hash_out_type);
                            size_t l_certs_field_size = l_token_size - sizeof(*l_token) - l_token->header_native_decl.tsd_total_size;
                            dap_chain_datum_token_certs_dump(a_str_out, l_token->data_n_tsd + l_token->header_native_decl.tsd_total_size,
                                                             l_certs_field_size, a_hash_out_type);
                        } break;
                        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC: {
                            dap_chain_addr_t l_premine_addr = l_token->header_public.premine_address;
                            dap_string_append(a_str_out, "subtype: PUBLIC\n");
                            dap_string_append_printf(a_str_out, "premine_supply: %s", dap_uint256_to_char(l_token->header_public.premine_supply, NULL));
                            dap_string_append_printf(a_str_out, "premine_address: %s", dap_chain_addr_to_str(&l_premine_addr));
                            dap_string_append(a_str_out, "flags: ");
                            dap_chain_datum_token_flags_dump(a_str_out, l_token->header_public.flags);
                        } break;
                    }
                } break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE: {
                    dap_string_append(a_str_out,"type: UPDATE\n");
                    switch (l_token->subtype) {
                        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE: {
                            dap_string_append(a_str_out,"subtype: PRIVATE\n");
                            dap_string_append_printf(a_str_out, "decimals: %d\n", l_token->header_private_decl.decimals);
                            dap_string_append_printf(a_str_out, "auth signs (valid/total) %u/%u\n", l_token->signs_valid, l_token->signs_total);
                            dap_string_append_printf(a_str_out, "total_supply: %s\n", dap_uint256_to_char(l_token->total_supply, NULL));
                            dap_string_append(a_str_out,"flags: ");
                            dap_chain_datum_token_flags_dump(a_str_out, l_token->header_private_update.flags);
                            dap_chain_datum_token_dump_tsd(a_str_out, l_token, l_token_size, a_hash_out_type);
                            size_t l_certs_field_size = l_token_size - sizeof(*l_token) - l_token->header_private_update.tsd_total_size;
                            dap_chain_datum_token_certs_dump(a_str_out, l_token->data_n_tsd + l_token->header_private_update.tsd_total_size,
                                                             l_certs_field_size, a_hash_out_type);
                        } break;
                        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE: {
                            dap_string_append_printf(a_str_out,"subtype: CF20\n");
                            dap_string_append_printf(a_str_out, "decimals: %d\n", l_token->header_native_update.decimals);
                            dap_string_append_printf(a_str_out, "auth signs (valid/total) %u/%u\n", l_token->signs_valid, l_token->signs_total);
                            dap_string_append_printf(a_str_out, "total_supply: %s\n", dap_uint256_to_char(l_token->total_supply, NULL));
                            dap_string_append(a_str_out, "flags: ");
                            dap_chain_datum_token_flags_dump(a_str_out, l_token->header_native_update.flags);
                            dap_chain_datum_token_dump_tsd(a_str_out, l_token, l_token_size, a_hash_out_type);
                            size_t l_certs_field_size = l_token_size - sizeof(*l_token) - l_token->header_native_update.tsd_total_size;
                            dap_chain_datum_token_certs_dump(a_str_out, l_token->data_n_tsd + l_token->header_native_update.tsd_total_size,
                                                             l_certs_field_size, a_hash_out_type);
                        } break;
                    }
                } break;
                default:
                    dap_string_append(a_str_out,"type: UNKNOWN\n");
                    break;
            }
            if (l_token->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE ) {
                dap_string_append(a_str_out, "subtype: SIMPLE\n");
                dap_string_append_printf(a_str_out, "decimals: %d\n", l_token->header_simple.decimals);
                dap_string_append_printf(a_str_out, "sign_total: %hu\n", l_token->signs_total );
                dap_string_append_printf(a_str_out, "sign_valid: %hu\n", l_token->signs_valid );
                dap_string_append_printf(a_str_out, "total_supply: %s\n", dap_uint256_to_char(l_token->total_supply, NULL));
                size_t l_certs_field_size = l_token_size - sizeof(*l_token);
                dap_chain_datum_token_certs_dump(a_str_out, l_token->data_n_tsd,
                                                 l_certs_field_size, a_hash_out_type);
            }
            DAP_DELETE(l_token);
        } break;
        case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
            size_t l_emission_size = a_datum->header.data_size;
            dap_chain_datum_token_emission_t *l_emission = dap_chain_datum_emission_read(a_datum->data, &l_emission_size);
            const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_emission->hdr.value, &l_coins_str);
            dap_string_append_printf(a_str_out, "emission: hash %s\n\t%s(%s) %s, type: %s, version: %d\n",
                                    l_hash_str,
                                    l_coins_str,
                                    l_value_str,
                                    l_emission->hdr.ticker,
                                    c_dap_chain_datum_token_emission_type_str[l_emission->hdr.type],
                                    l_emission->hdr.version);
            dap_string_append_printf(a_str_out, "  to addr: %s\n", dap_chain_addr_to_str(&(l_emission->hdr.address)));
            switch (l_emission->hdr.type) {
            case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH:
                dap_string_append_printf(a_str_out, "  signs_count: %d\n", l_emission->data.type_auth.signs_count);
                dap_string_append_printf(a_str_out, "  tsd_total_size: %"DAP_UINT64_FORMAT_U"\n",
                                         l_emission->data.type_auth.tsd_total_size);

                if (  ( (void *) l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size) >
                      ((void *) l_emission + l_emission_size) )
                {
                    log_it(L_ERROR, "Illformed DATUM type %d, TSD section is out-of-buffer (%" DAP_UINT64_FORMAT_U " vs %zu)",
                        l_emission->hdr.type, l_emission->data.type_auth.tsd_total_size, l_emission_size);
                    dap_string_append_printf(a_str_out, "  Skip incorrect or illformed DATUM");
                    break;
                }
                dap_chain_datum_token_certs_dump(a_str_out, l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size,
                                                l_emission->data.type_auth.size - l_emission->data.type_auth.tsd_total_size, a_hash_out_type);
                break;
            case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ALGO:
                dap_string_append_printf(a_str_out, "  codename: %s\n", l_emission->data.type_algo.codename);
                break;
            case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_SMART_CONTRACT: {
                char l_time_str[32];
                // get time of create datum
                if(dap_time_to_str_rfc822(l_time_str, sizeof(l_time_str), l_emission->data.type_presale.lock_time) < 1)
                        l_time_str[0] = '\0';
                dap_string_append_printf(a_str_out, "  flags: 0x%x, lock_time: %s\n", l_emission->data.type_presale.flags, l_time_str);
                dap_string_append_printf(a_str_out, "  addr: %s\n", dap_chain_addr_to_str(&l_emission->data.type_presale.addr));
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
            dap_chain_datum_dump_tx(l_tx, NULL, a_str_out, a_hash_out_type, &l_datum_hash, a_net_id);
        } break;
        case DAP_CHAIN_DATUM_DECREE:{
            dap_chain_datum_decree_t *l_decree = (dap_chain_datum_decree_t *)a_datum->data;
            size_t l_decree_size = dap_chain_datum_decree_get_size(l_decree);
            dap_string_append_printf(a_str_out,"=== Datum decree ===\n");
            dap_string_append_printf(a_str_out, "hash: %s\n", l_hash_str);
            dap_string_append_printf(a_str_out, "size: %zd\n", l_decree_size);
            dap_chain_datum_decree_dump(a_str_out, l_decree, l_decree_size, a_hash_out_type);
        } break;
        case DAP_CHAIN_DATUM_ANCHOR:{
            dap_chain_datum_anchor_t *l_anchor = (dap_chain_datum_anchor_t *)a_datum->data;
            size_t l_anchor_size = sizeof(dap_chain_datum_anchor_t) + l_anchor->header.data_size + l_anchor->header.signs_size;
            dap_string_append_printf(a_str_out,"=== Datum anchor ===\n");
            dap_string_append_printf(a_str_out, "hash: %s\n", l_hash_str);
            dap_string_append_printf(a_str_out, "size: %zd\n", l_anchor_size);
            dap_hash_fast_t l_decree_hash = { };
            dap_chain_datum_anchor_get_hash_from_data(l_anchor, &l_decree_hash);
            l_hash_str = dap_chain_hash_fast_to_str_static(&l_decree_hash);
            dap_string_append_printf(a_str_out, "decree hash: %s\n", l_hash_str);
            dap_chain_datum_anchor_certs_dump(a_str_out, l_anchor->data_n_sign + l_anchor->header.data_size, l_anchor->header.signs_size, a_hash_out_type);
        } break;
    }    
}



/**
 * @brief dap_chain_net_dump_datum
 * process datum verification process. Can be:
 * if DAP_CHAIN_DATUM_TX, called dap_ledger_tx_add_check
 * if DAP_CHAIN_DATUM_TOKEN_DECL, called dap_ledger_token_decl_add_check
 * if DAP_CHAIN_DATUM_TOKEN_EMISSION, called dap_ledger_token_emission_add_check
 * @param a_obj_out
 * @param a_datum
 */
void dap_chain_datum_dump_json(json_object  *a_obj_out, dap_chain_datum_t *a_datum, const char *a_hash_out_type, dap_chain_net_id_t a_net_id)
{
    if( a_datum == NULL){
        dap_json_rpc_error_add(-1,"==Datum is NULL");
        return;
    }
    json_object * json_obj_datum = json_object_new_object();
    dap_hash_fast_t l_datum_hash;
    dap_hash_fast(a_datum->data, a_datum->header.data_size, &l_datum_hash);
    const char *l_hash_str = dap_strcmp(a_hash_out_type, "hex")
            ? dap_enc_base58_encode_hash_to_str_static(&l_datum_hash)
            : dap_chain_hash_fast_to_str_static(&l_datum_hash);
    switch (a_datum->header.type_id) {
        case DAP_CHAIN_DATUM_TOKEN_DECL: {
            size_t l_token_size = a_datum->header.data_size;
            dap_chain_datum_token_t * l_token = dap_chain_datum_token_read(a_datum->data, &l_token_size);
            if(l_token_size < sizeof(dap_chain_datum_token_t)){
                dap_json_rpc_error_add(-2,"==Datum has incorrect size. Only %zu, while at least %zu is expected\n",
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
                            json_object_object_add(json_obj_datum,"Flags",json_object_new_string(""));

                            dap_chain_datum_token_flags_dump_to_json(json_obj_datum,l_token->header_private_update.flags);
                            dap_datum_token_dump_tsd_to_json(json_obj_datum,l_token, l_token_size, a_hash_out_type);               
                            size_t l_certs_field_size = l_token_size - sizeof(*l_token) - l_token->header_private_update.tsd_total_size;
                            dap_chain_datum_token_certs_dump_to_json(json_obj_datum,l_token->data_n_tsd + l_token->header_private_update.tsd_total_size,
                                                             l_certs_field_size, a_hash_out_type);                            
                        } break;
                        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE: {
                            json_object_object_add(json_obj_datum,"subtype",json_object_new_string("CF20"));
                            json_object_object_add(json_obj_datum,"decimals",json_object_new_uint64(l_token->header_native_decl.decimals));
                            json_object_object_add(json_obj_datum,"auth signs valid",json_object_new_uint64(l_token->signs_valid));
                            json_object_object_add(json_obj_datum,"auth signs total",json_object_new_uint64(l_token->signs_total));
                            json_object_object_add(json_obj_datum,"total_supply",json_object_new_string(dap_uint256_to_char(l_token->total_supply, NULL)));
                            json_object_object_add(json_obj_datum,"Flags",json_object_new_string(""));

                            dap_chain_datum_token_flags_dump_to_json(json_obj_datum, l_token->header_native_decl.flags);
                            dap_datum_token_dump_tsd_to_json(json_obj_datum, l_token, l_token_size, a_hash_out_type);
                            size_t l_certs_field_size = l_token_size - sizeof(*l_token) - l_token->header_native_decl.tsd_total_size;
                            dap_chain_datum_token_certs_dump_to_json(json_obj_datum, l_token->data_n_tsd + l_token->header_native_decl.tsd_total_size,
                                                             l_certs_field_size, a_hash_out_type);
                        } break;
                        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC: {
                            dap_chain_addr_t l_premine_addr = l_token->header_public.premine_address;
                            json_object_object_add(json_obj_datum,"subtype",json_object_new_string("PUBLIC"));
                            json_object_object_add(json_obj_datum,"premine_supply", json_object_new_string(dap_uint256_to_char(l_token->header_public.premine_supply, NULL)));
                            json_object_object_add(json_obj_datum,"premine_address", json_object_new_string(dap_chain_addr_to_str(&l_premine_addr)));

                            json_object_object_add(json_obj_datum,"Flags",json_object_new_string(""));
                            dap_chain_datum_token_flags_dump_to_json(json_obj_datum, l_token->header_public.flags);
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
                            
                            json_object_object_add(json_obj_datum,"Flags",json_object_new_string(""));
                            dap_chain_datum_token_flags_dump_to_json(json_obj_datum, l_token->header_private_update.flags);
                            dap_datum_token_dump_tsd_to_json(json_obj_datum, l_token, l_token_size, a_hash_out_type);
                            size_t l_certs_field_size = l_token_size - sizeof(*l_token) - l_token->header_private_update.tsd_total_size;
                            dap_chain_datum_token_certs_dump_to_json(json_obj_datum, l_token->data_n_tsd + l_token->header_private_update.tsd_total_size,
                                                             l_certs_field_size, a_hash_out_type);
                        } break;
                        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE: {
                            json_object_object_add(json_obj_datum,"subtype", json_object_new_string("CF20"));
                            json_object_object_add(json_obj_datum,"decimals", json_object_new_uint64(l_token->header_native_update.decimals));
                            json_object_object_add(json_obj_datum,"auth signs valid",json_object_new_uint64(l_token->signs_valid));
                            json_object_object_add(json_obj_datum,"auth signs total",json_object_new_uint64(l_token->signs_total));
                            json_object_object_add(json_obj_datum,"total_supply",json_object_new_string(dap_uint256_to_char(l_token->total_supply, NULL)));
                            
                            json_object_object_add(json_obj_datum,"Flags",json_object_new_string(""));
                            dap_chain_datum_token_flags_dump_to_json(json_obj_datum, l_token->header_native_update.flags);
                            dap_datum_token_dump_tsd_to_json(json_obj_datum, l_token, l_token_size, a_hash_out_type);
                            size_t l_certs_field_size = l_token_size - sizeof(*l_token) - l_token->header_native_update.tsd_total_size;
                            dap_chain_datum_token_certs_dump_to_json(json_obj_datum, l_token->data_n_tsd + l_token->header_native_update.tsd_total_size,
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
                dap_chain_datum_token_certs_dump_to_json(json_obj_datum, l_token->data_n_tsd,
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
            json_object_object_add(json_obj_datum,"type", json_object_new_string(c_dap_chain_datum_token_emission_type_str[l_emission->hdr.type]));
            json_object_object_add(json_obj_datum,"version", json_object_new_uint64(l_emission->hdr.version));
            json_object_object_add(json_obj_datum,"to addr", json_object_new_string(dap_chain_addr_to_str(&(l_emission->hdr.address))));

            switch (l_emission->hdr.type) {
            case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH:
                json_object_object_add(json_obj_datum,"signs_count", json_object_new_uint64(l_emission->data.type_auth.signs_count));
                json_object_object_add(json_obj_datum,"tsd_total_size", json_object_new_uint64(l_emission->data.type_auth.tsd_total_size));

                if (  ( (void *) l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size) >
                      ((void *) l_emission + l_emission_size) )
                {
                    log_it(L_ERROR, "Illformed DATUM type %d, TSD section is out-of-buffer (%" DAP_UINT64_FORMAT_U " vs %zu)",
                        l_emission->hdr.type, l_emission->data.type_auth.tsd_total_size, l_emission_size);
                    dap_json_rpc_error_add(-3,"Skip incorrect or illformed DATUM");
                    break;
                }
                dap_chain_datum_token_certs_dump_to_json(json_obj_datum, l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size,
                                                l_emission->data.type_auth.size - l_emission->data.type_auth.tsd_total_size, a_hash_out_type);
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
                json_object_object_add(json_obj_datum,"addr", json_object_new_string(dap_chain_addr_to_str(&l_emission->data.type_presale.addr)));                
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
            dap_chain_datum_dump_tx_json(l_tx, NULL, json_obj_datum, a_hash_out_type, &l_datum_hash, a_net_id);
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
