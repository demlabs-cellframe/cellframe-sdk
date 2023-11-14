/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2019
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

#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>

#include "dap_chain_wallet.h"
#include "dap_common.h"
#include "dap_enc_base58.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_list.h"
#include "dap_hash.h"
#include "dap_time.h"

#include "dap_chain_cell.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd_tx.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_mempool.h"
#include "dap_math_convert.h"

#define LOG_TAG "chain_node_cli_cmd_tx"

#include "uthash.h"
// for dap_db_history_filter()
typedef struct dap_tx_data {
    dap_chain_hash_fast_t tx_hash;
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_datum_t *datum;
    UT_hash_handle hh;
    //useless
    char tx_hash_str[70];
    dap_chain_addr_t addr;
} dap_tx_data_t;

typedef struct dap_chain_tx_hash_processed_ht{
    dap_chain_hash_fast_t hash;
    UT_hash_handle hh;
}dap_chain_tx_hash_processed_ht_t;


/**
 * @brief s_chain_tx_hash_processed_ht_free
 * free l_current_hash->hash, l_current_hash, l_hash_processed
 * @param l_hash_processed dap_chain_tx_hash_processed_ht_t
 */
static void s_dap_chain_tx_hash_processed_ht_free(dap_chain_tx_hash_processed_ht_t **l_hash_processed)
{
    if (!l_hash_processed || !*l_hash_processed)
        return;
    dap_chain_tx_hash_processed_ht_t *l_tmp, *l_current_hash;
    HASH_ITER(hh, *l_hash_processed, l_current_hash, l_tmp) {
        HASH_DEL(*l_hash_processed, l_current_hash);
        DAP_DELETE(l_current_hash);
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

static bool s_dap_chain_datum_tx_out_data(dap_chain_datum_tx_t *a_datum,
                                          dap_ledger_t *a_ledger,
                                          dap_string_t *a_str_out,
                                          const char *a_hash_out_type,
                                          dap_chain_hash_fast_t *a_tx_hash)
{
    const char *l_ticker = a_ledger
            ? dap_ledger_tx_get_token_ticker_by_hash(a_ledger, a_tx_hash)
            : NULL;
    if (!l_ticker)
        return false;
    dap_chain_datum_dump_tx(a_datum, l_ticker, a_str_out, a_hash_out_type, a_tx_hash, a_ledger->net->pub.id);
    dap_list_t *l_out_items = dap_chain_datum_tx_items_get(a_datum, TX_ITEM_TYPE_OUT_ALL, NULL);
    int l_out_idx = 0;
    dap_string_append_printf(a_str_out, "Spent OUTs:\r\n");
    bool l_spent = false;
    for (dap_list_t *l_item = l_out_items; l_item; l_item = l_item->next, ++l_out_idx) {
        switch (*(dap_chain_tx_item_type_t*)l_item->data) {
        case TX_ITEM_TYPE_OUT:
        case TX_ITEM_TYPE_OUT_OLD:
        case TX_ITEM_TYPE_OUT_EXT:
        case TX_ITEM_TYPE_OUT_COND_OLD:
        case TX_ITEM_TYPE_OUT_COND: {
            dap_hash_fast_t l_spender = { };
            if (dap_ledger_tx_hash_is_used_out_item(a_ledger, a_tx_hash, l_out_idx, &l_spender)) {
                char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' };
                dap_hash_fast_to_str(&l_spender, l_hash_str, sizeof(l_hash_str));
                dap_string_append_printf(a_str_out,
                                         "\tOUT %d is spent by tx %s\r\n",
                                         l_out_idx, l_hash_str);
                l_spent = true;
            }
            break;
        }
        default:
            break;
        }
    }
    dap_string_append_printf(a_str_out, l_spent ? "\r\n\r\n" : "\tall OUTs yet unspent\r\n\r\n");
    return true;
}

/**
 * @brief dap_db_history_tx
 * Get data according the history log
 *
 * return history string
 * @param a_tx_hash
 * @param a_chain
 * @param a_hash_out_type
 * @return char*
 */
char* dap_db_history_tx(dap_chain_hash_fast_t* a_tx_hash, dap_chain_t * a_chain, const char *a_hash_out_type)
{
    if (!a_chain->callback_datum_find_by_hash) {
        log_it(L_WARNING, "Not defined callback_datum_find_by_hash for chain \"%s\"", a_chain->name);
        return NULL;
    }

    dap_string_t *l_str_out = dap_string_new(NULL);
    dap_hash_fast_t l_atom_hash = {};
    int l_ret_code = 0;
    dap_chain_datum_t *l_datum = a_chain->callback_datum_find_by_hash(a_chain, a_tx_hash, &l_atom_hash, &l_ret_code);
    dap_chain_datum_tx_t *l_tx = l_datum  && l_datum->header.type_id == DAP_CHAIN_DATUM_TX ?
                                 (dap_chain_datum_tx_t *)l_datum->data : NULL;

    if (l_tx) {
        char *l_atom_hash_str = dap_strcmp(a_hash_out_type, "hex")
                ? dap_enc_base58_encode_hash_to_str(&l_atom_hash)
                : dap_chain_hash_fast_to_str_new(&l_atom_hash);
        dap_ledger_t *l_ledger = dap_chain_net_by_id(a_chain->net_id)->pub.ledger;
        const char *l_tx_token_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, a_tx_hash);
        dap_string_append_printf(l_str_out, "%s TX with atom %s (ret_code %d - %s)\n", l_tx_token_ticker ? "ACCEPTED" : "DECLINED",
                                                                    l_atom_hash_str, l_ret_code, dap_ledger_tx_check_err_str(l_ret_code));
        DAP_DELETE(l_atom_hash_str);
        dap_chain_datum_dump_tx(l_tx, l_tx_token_ticker, l_str_out, a_hash_out_type, a_tx_hash, a_chain->net_id);
    } else {
        char *l_tx_hash_str = dap_strcmp(a_hash_out_type, "hex")
                ? dap_enc_base58_encode_hash_to_str(a_tx_hash)
                : dap_chain_hash_fast_to_str_new(a_tx_hash);
        dap_string_append_printf(l_str_out, "TX hash %s not founds in chains", l_tx_hash_str);
        DAP_DELETE(l_tx_hash_str);
    }
    return l_str_out ? dap_string_free(l_str_out, false) : NULL;
}

static void s_tx_header_print(dap_string_t *a_str_out, dap_chain_tx_hash_processed_ht_t **a_tx_data_ht,
                              dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_atom_hash,
                              const char *a_hash_out_type, dap_ledger_t *a_ledger,
                              dap_chain_hash_fast_t *a_tx_hash, int a_ret_code)
{
    bool l_declined = false;
    // transaction time
    char l_time_str[32] = "unknown";                                /* Prefill string */
    if (a_tx->header.ts_created) {
        uint64_t l_ts = a_tx->header.ts_created;
        dap_ctime_r(&l_ts, l_time_str);                             /* Convert ts to  Sat May 17 01:17:08 2014 */
    }
    dap_chain_tx_hash_processed_ht_t *l_tx_data = NULL;
    HASH_FIND(hh, *a_tx_data_ht, a_tx_hash, sizeof(*a_tx_hash), l_tx_data);
    if (l_tx_data)  // this tx already present in ledger (double)
        l_declined = true;
    else {
        l_tx_data = DAP_NEW_Z(dap_chain_tx_hash_processed_ht_t);
        if (!l_tx_data) {
            log_it(L_CRITICAL, "Memory allocation error");
            return;
        }
        l_tx_data->hash = *a_tx_hash;
        HASH_ADD(hh, *a_tx_data_ht, hash, sizeof(*a_tx_hash), l_tx_data);
        const char *l_token_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, a_tx_hash);
        if (!l_token_ticker)
            l_declined = true;
    }
    char *l_tx_hash_str, *l_atom_hash_str;
    if (!dap_strcmp(a_hash_out_type, "hex")) {
        l_tx_hash_str = dap_chain_hash_fast_to_str_new(a_tx_hash);
        l_atom_hash_str = dap_chain_hash_fast_to_str_new(a_atom_hash);
    } else {
        l_tx_hash_str = dap_enc_base58_encode_hash_to_str(a_tx_hash);
        l_atom_hash_str = dap_enc_base58_encode_hash_to_str(a_atom_hash);
    }
    dap_string_append_printf(a_str_out, "%s TX hash %s with atom %s (ret code %d - %s) \n\t%s", l_declined ? "DECLINED" : "ACCEPTED",
                                                                          l_tx_hash_str, l_atom_hash_str, a_ret_code,
                                                                          dap_ledger_tx_check_err_str(a_ret_code), l_time_str);
    DAP_DELETE(l_tx_hash_str);
    DAP_DELETE(l_atom_hash_str);
}

/**
 * @brief dap_db_history_addr
 * Get data according the history log
 *
 * return history string
 * @param a_addr
 * @param a_chain
 * @param a_hash_out_type
 * @return char*
 */
char* dap_db_history_addr(dap_chain_addr_t *a_addr, dap_chain_t *a_chain, const char *a_hash_out_type)
{
    struct token_addr {
        const char token[DAP_CHAIN_TICKER_SIZE_MAX];
        dap_chain_addr_t addr;
    };

    dap_string_t *l_str_out = dap_string_new(NULL);
    if (!l_str_out) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    dap_chain_tx_hash_processed_ht_t *l_tx_data_ht = NULL;
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    if (!l_net) {
        log_it(L_WARNING, "Can't find net by specified chain %s", a_chain->name);
        return NULL;
    }
    dap_ledger_t *l_ledger = l_net->pub.ledger;
    const char *l_native_ticker = l_net->pub.native_ticker;
    if (!a_chain->callback_datum_iter_create) {
        log_it(L_WARNING, "Not defined callback_datum_iter_create for chain \"%s\"", a_chain->name);
        return NULL;
    }
    // load transactions
    dap_chain_datum_iter_t *l_datum_iter = a_chain->callback_datum_iter_create(a_chain);

    for (dap_chain_datum_t *l_datum = a_chain->callback_datum_iter_get_first(l_datum_iter);
                            l_datum;
                            l_datum = a_chain->callback_datum_iter_get_next(l_datum_iter))
    {
        if (l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
            // go to next datum
            continue;
        // it's a transaction
        dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)l_datum->data;
        dap_list_t *l_list_in_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN_ALL, NULL);
        if (!l_list_in_items) // a bad tx
            continue;
        // all in items should be from the same address
        dap_chain_addr_t *l_src_addr = NULL;
        bool l_base_tx = false;
        const char *l_noaddr_token = NULL;

        dap_hash_fast_t l_tx_hash;
        dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
        const char *l_src_token = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_tx_hash);

        int l_src_subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED;
        for (dap_list_t *it = l_list_in_items; it; it = it->next) {
            dap_chain_hash_fast_t *l_tx_prev_hash;
            int l_tx_prev_out_idx;
            dap_chain_datum_tx_t *l_tx_prev = NULL;
            switch (*(byte_t *)it->data) {
            case TX_ITEM_TYPE_IN: {
                dap_chain_tx_in_t *l_tx_in = (dap_chain_tx_in_t *)it->data;
                l_tx_prev_hash = &l_tx_in->header.tx_prev_hash;
                l_tx_prev_out_idx = l_tx_in->header.tx_out_prev_idx;
            } break;
            case TX_ITEM_TYPE_IN_COND: {
                dap_chain_tx_in_cond_t *l_tx_in_cond = (dap_chain_tx_in_cond_t *)it->data;
                l_tx_prev_hash = &l_tx_in_cond->header.tx_prev_hash;
                l_tx_prev_out_idx = l_tx_in_cond->header.tx_out_prev_idx;
            } break;
            case TX_ITEM_TYPE_IN_EMS: {
                dap_chain_tx_in_ems_t *l_in_ems = (dap_chain_tx_in_ems_t *)it->data;
                l_base_tx = true;
                l_noaddr_token = l_in_ems->header.ticker;
            }
            default:
                continue;
            }

            dap_chain_datum_t *l_datum = a_chain->callback_datum_find_by_hash(a_chain, l_tx_prev_hash, NULL, NULL);
            l_tx_prev = l_datum  && l_datum->header.type_id == DAP_CHAIN_DATUM_TX ? (dap_chain_datum_tx_t *)l_datum->data : NULL;
            if (l_tx_prev) {
                uint8_t *l_prev_out_union = dap_chain_datum_tx_item_get_nth(l_tx_prev, TX_ITEM_TYPE_OUT_ALL, l_tx_prev_out_idx);
                if (!l_prev_out_union)
                    continue;
                switch (*l_prev_out_union) {
                case TX_ITEM_TYPE_OUT:
                    l_src_addr = &((dap_chain_tx_out_t *)l_prev_out_union)->addr;
                    break;
                case TX_ITEM_TYPE_OUT_EXT:
                    l_src_addr = &((dap_chain_tx_out_ext_t *)l_prev_out_union)->addr;
                    break;
                case TX_ITEM_TYPE_OUT_COND:
                    l_src_subtype = ((dap_chain_tx_out_cond_t *)l_prev_out_union)->header.subtype;
                    if (l_src_subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)
                        l_noaddr_token = l_native_ticker;
                    else
                        l_noaddr_token = l_src_token;
                default:
                    break;
                }
            }
            if (l_src_addr && !dap_chain_addr_compare(l_src_addr, a_addr))
                break;  //it's not our addr
        }
        dap_list_free(l_list_in_items);

        // find OUT items
        bool l_header_printed = false;
        uint256_t l_fee_sum = {};
        dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
        for (dap_list_t *it = l_list_out_items; it; it = it->next) {
            dap_chain_addr_t *l_dst_addr = NULL;
            uint8_t l_type = *(uint8_t *)it->data;
            uint256_t l_value;
            const char *l_dst_token = NULL;
            switch (l_type) {
            case TX_ITEM_TYPE_OUT:
                l_dst_addr = &((dap_chain_tx_out_t *)it->data)->addr;
                l_value = ((dap_chain_tx_out_t *)it->data)->header.value;
                l_dst_token = l_src_token;
                break;
            case TX_ITEM_TYPE_OUT_EXT:
                l_dst_addr = &((dap_chain_tx_out_ext_t *)it->data)->addr;
                l_value = ((dap_chain_tx_out_ext_t *)it->data)->header.value;
                l_dst_token = ((dap_chain_tx_out_ext_t *)it->data)->token;
                break;
            case TX_ITEM_TYPE_OUT_COND:
                l_value = ((dap_chain_tx_out_cond_t *)it->data)->header.value;
                if (((dap_chain_tx_out_cond_t *)it->data)->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE) {
                    SUM_256_256(l_fee_sum, ((dap_chain_tx_out_cond_t *)it->data)->header.value, &l_fee_sum);
                    l_dst_token = l_native_ticker;
                } else
                    l_dst_token = l_src_token;
            default:
                break;
            }
            if (l_src_addr && l_dst_addr && dap_chain_addr_compare(l_dst_addr, l_src_addr) &&
                    dap_strcmp(l_dst_token, l_noaddr_token))
                continue;   // sent to self (coinback)
            if (l_src_addr && dap_chain_addr_compare(l_src_addr, a_addr) &&
                    dap_strcmp(l_dst_token, l_noaddr_token)) {
                if (!l_header_printed) {
                    s_tx_header_print(l_str_out, &l_tx_data_ht, l_tx, l_datum_iter->cur_atom_hash,
                                      a_hash_out_type, l_ledger, &l_tx_hash, l_datum_iter->ret_code);
                    l_header_printed = true;
                }
                const char *l_dst_addr_str = l_dst_addr ? dap_chain_addr_to_str(l_dst_addr)
                                                        : dap_chain_tx_out_cond_subtype_to_str(
                                                              ((dap_chain_tx_out_cond_t *)it->data)->header.subtype);
                char *l_value_str = dap_chain_balance_print(l_value);
                char *l_coins_str = dap_chain_balance_to_coins(l_value);
                dap_string_append_printf(l_str_out, "\tsend %s (%s) %s to %s\n",
                                         l_coins_str,
                                         l_value_str,
                                         l_dst_token ? l_dst_token : "UNKNOWN",
                                         l_dst_addr_str);
                if (l_dst_addr)
                    DAP_DELETE(l_dst_addr_str);
                DAP_DELETE(l_value_str);
                DAP_DELETE(l_coins_str);
            }
            if (l_dst_addr && dap_chain_addr_compare(l_dst_addr, a_addr)) {
                if (!l_header_printed) {
                    s_tx_header_print(l_str_out, &l_tx_data_ht, l_tx, l_datum_iter->cur_atom_hash,
                                      a_hash_out_type, l_ledger, &l_tx_hash, l_datum_iter->ret_code);
                    l_header_printed = true;
                }
                const char *l_src_addr_str = NULL, *l_src_str;
                if (l_base_tx)
                    l_src_str = "emission";
                else if (l_src_addr && dap_strcmp(l_dst_token, l_noaddr_token))
                    l_src_str = l_src_addr_str = dap_chain_addr_to_str(l_src_addr);
                else
                    l_src_str = dap_chain_tx_out_cond_subtype_to_str(l_src_subtype);
                char *l_value_str = dap_chain_balance_print(l_value);
                char *l_coins_str = dap_chain_balance_to_coins(l_value);
                dap_string_append_printf(l_str_out, "\trecv %s (%s) %s from %s\n",
                                         l_coins_str,
                                         l_value_str,
                                         l_dst_token ? l_dst_token : "UNKNOWN",
                                         l_src_str);
                DAP_DEL_Z(l_src_addr_str);
                DAP_DELETE(l_value_str);
                DAP_DELETE(l_coins_str);
            }
        }
        dap_list_free(l_list_out_items);
        // fee for base TX in native token
        if (l_header_printed && l_base_tx && !dap_strcmp(l_native_ticker, l_src_token)) {
            char *l_fee_value_str = dap_chain_balance_print(l_fee_sum);
            char *l_fee_coins_str = dap_chain_balance_to_coins(l_fee_sum);
            dap_string_append_printf(l_str_out, "\t\tpay %s (%s) fee\n",
                                               l_fee_value_str, l_fee_coins_str);
            DAP_DELETE(l_fee_value_str);
            DAP_DELETE(l_fee_coins_str);
        }
    }
    a_chain->callback_datum_iter_delete(l_datum_iter);
    // delete hashes
    s_dap_chain_tx_hash_processed_ht_free(&l_tx_data_ht);
    // if no history
    if(!l_str_out->len)
        dap_string_append(l_str_out, "\tempty");
    return l_str_out ? dap_string_free(l_str_out, false) : NULL;
}

/**
 * @brief show all tokens in chain
 *
 * @param a_chain
 * @param a_token_name
 * @param a_hash_out_type
 * @param a_token_num
 * @return char*
 */
static char* dap_db_chain_history_token_list(dap_chain_t * a_chain, const char *a_token_name, const char *a_hash_out_type, size_t *a_token_num) {
    if (!a_chain->callback_atom_get_datums) {
        log_it(L_WARNING, "Not defined callback_atom_get_datums for chain \"%s\"", a_chain->name);
        return NULL;
    }
    dap_string_t *l_str_out = dap_string_new(NULL);
    if (!l_str_out) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    *a_token_num  = 0;
    size_t l_atom_size = 0;
    dap_chain_cell_t *l_cell = a_chain->cells;
    do {
        dap_chain_atom_iter_t *l_atom_iter = a_chain->callback_atom_iter_create(a_chain, l_cell->id, 0);
        if(!a_chain->callback_atom_get_datums) {
            log_it(L_DEBUG, "Not defined callback_atom_get_datums for chain \"%s\"", a_chain->name);
            return NULL ;
        }
        for (dap_chain_atom_ptr_t l_atom = a_chain->callback_atom_iter_get_first(l_atom_iter, &l_atom_size);
                l_atom && l_atom_size; l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter, &l_atom_size)) {
            size_t l_datums_count = 0;
            dap_chain_datum_t **l_datums = a_chain->callback_atom_get_datums(l_atom, l_atom_size, &l_datums_count);
            for(size_t l_datum_n = 0; l_datum_n < l_datums_count; l_datum_n++) {
                dap_chain_datum_t *l_datum = l_datums[l_datum_n];
                if (!l_datum || l_datum->header.type_id != DAP_CHAIN_DATUM_TOKEN_DECL)
                    continue;
                if (a_token_name) {
                    size_t l_token_size = l_datum->header.data_size;
                    dap_chain_datum_token_t *l_token = dap_chain_datum_token_read(l_datum->data, &l_token_size);
                    int l_cmp = dap_strcmp(l_token->ticker, a_token_name);
                    DAP_DELETE(l_token);
                    if (l_cmp)
                        continue;
                }
                dap_chain_datum_dump(l_str_out, l_datum, a_hash_out_type, a_chain->net_id);
                (*a_token_num)++;
            }
            DAP_DELETE(l_datums);
        }
        a_chain->callback_atom_iter_delete(l_atom_iter);
        l_cell = l_cell->hh.next;
    } while (l_cell);
    char *l_ret_str = l_str_out ? dap_string_free(l_str_out, false) : NULL;
    return l_ret_str;
}

/**
 * @brief show all tokens in all chains in net
 *
 * @param a_chain
 * @param a_token_name
 * @param a_hash_out_type
 * @param a_token_num
 * @return char*
 */

static size_t dap_db_net_history_token_list(dap_chain_net_t * l_net, const char *a_token_name, const char *a_hash_out_type, dap_string_t *a_str_out) {
    size_t l_token_num_total = 0;
    dap_chain_t *l_chain_cur;
    DL_FOREACH(l_net->pub.chains, l_chain_cur) {
        size_t l_token_num = 0;
        char *token_list_str = dap_db_chain_history_token_list(l_chain_cur, a_token_name, a_hash_out_type, &l_token_num);
        if(token_list_str)
            dap_string_append(a_str_out, token_list_str);
        l_token_num_total += l_token_num;
        DAP_DEL_Z(token_list_str);
    }
    return l_token_num_total;
}

/**
 * @brief dap_db_history_filter
 * Get data according the history log
 *
 * return history string
 * @param a_chain
 * @param a_ledger
 * @param a_filter_token_name
 * @param a_filtr_addr_base58
 * @param a_hash_out_type
 * @param a_datum_start
 * @param a_datum_end
 * @param a_total_datums
 * @param a_tx_hash_processed
 * @return char*
 */
static char* dap_db_history_filter(dap_chain_t * a_chain, dap_ledger_t *a_ledger, const char *a_filter_token_name, const char *a_filtr_addr_base58, const char *a_hash_out_type, long a_datum_start, long a_datum_end, long *a_total_datums, dap_chain_tx_hash_processed_ht_t *a_tx_hash_processed)
{
    if (!a_chain->callback_atom_get_datums) {
        log_it(L_WARNING, "Not defined callback_atom_get_datums for chain \"%s\"", a_chain->name);
        return NULL;
    }
    dap_string_t *l_str_out = dap_string_new(NULL);
    if (!l_str_out) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    // list all transactions
    dap_tx_data_t *l_tx_data_hash = NULL;
    dap_chain_cell_t *l_cell = a_chain->cells;
    do {
        // load transactions
        size_t l_atom_size = 0;
        dap_chain_atom_iter_t *l_atom_iter = a_chain->callback_atom_iter_create(a_chain, l_cell->id, 0);
        size_t l_datum_num = 0, l_token_num = 0, l_emission_num = 0, l_tx_num = 0;
        size_t l_datum_num_global = a_total_datums ? *a_total_datums : 0;
        for (dap_chain_atom_ptr_t l_atom = a_chain->callback_atom_iter_get_first(l_atom_iter, &l_atom_size);
                l_atom && l_atom_size; l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter, &l_atom_size)) {
            size_t l_datums_count = 0;
            dap_chain_datum_t **l_datums = a_chain->callback_atom_get_datums(l_atom, l_atom_size, &l_datums_count);
            if (!l_datums || !l_datums_count)
                continue;
            for(size_t l_datum_n = 0; l_datum_n < l_datums_count; l_datum_n++) {
                dap_chain_datum_t *l_datum = l_datums[l_datum_n];
                if(!l_datum)
                    continue;
                char l_time_str[70];
                // get time of create datum
                if(dap_time_to_str_rfc822(l_time_str, 71, l_datum->header.ts_create) < 1)
                    l_time_str[0] = '\0';
                switch (l_datum->header.type_id) {
                // token
                case DAP_CHAIN_DATUM_TOKEN_DECL: {
                    // no token necessary for addr
                    if(a_filtr_addr_base58)
                        break;
                    dap_chain_datum_token_t *l_token = (dap_chain_datum_token_t*) l_datum->data;
                    //if(a_datum_start < 0 || (l_datum_num >= a_datum_start && l_datum_num < a_datum_end))
                    // datum out of page
                    if(a_datum_start >= 0 && (l_datum_num+l_datum_num_global < (size_t)a_datum_start || l_datum_num+l_datum_num_global >= (size_t)a_datum_end)){
                        l_token_num++;
                        break;
                    }
                    if(!a_filter_token_name || !dap_strcmp(l_token->ticker, a_filter_token_name)) {
                        dap_chain_datum_dump(l_str_out, l_datum, a_hash_out_type, a_chain->net_id);
                        dap_string_append(l_str_out, "\n");
                        l_token_num++;
                    }
                } break;

                // emission
                case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
                    // datum out of page
                    if(a_datum_start >= 0 && (l_datum_num+l_datum_num_global < (size_t)a_datum_start || l_datum_num+l_datum_num_global >= (size_t)a_datum_end)) {
                         l_emission_num++;
                         break;
                    }
                    dap_chain_datum_token_emission_t *l_token_em =  (dap_chain_datum_token_emission_t *)l_datum->data;
                    if(!a_filter_token_name || !dap_strcmp(l_token_em->hdr.ticker, a_filter_token_name)) {
                        char * l_token_emission_address_str = dap_chain_addr_to_str(&(l_token_em->hdr.address));
                        // filter for addr
                        if (a_filtr_addr_base58 && dap_strcmp(a_filtr_addr_base58, l_token_emission_address_str)) {
                             break;
                        }
                        dap_chain_datum_dump(l_str_out, l_datum, a_hash_out_type, a_chain->net_id);
                        dap_string_append(l_str_out, "\n");
                        l_emission_num++;
                    }
                } break;

                // transaction
                case DAP_CHAIN_DATUM_TX:{
                    // datum out of page
                    if(a_datum_start >= 0 && (l_datum_num+l_datum_num_global < (size_t)a_datum_start || l_datum_num+l_datum_num_global >= (size_t)a_datum_end)) {
                        l_tx_num++;
                        break;
                    }
                    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*)l_datum->data;
                    //calc tx hash
                    dap_chain_hash_fast_t l_tx_hash;
                    dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
                    dap_chain_tx_hash_processed_ht_t *l_sht = NULL;
                    HASH_FIND(hh, a_tx_hash_processed, &l_tx_hash, sizeof(dap_chain_hash_fast_t), l_sht);
                    if (l_sht != NULL ||
                            !s_dap_chain_datum_tx_out_data(l_tx, a_ledger, l_str_out, a_hash_out_type, &l_tx_hash)) {
                        l_datum_num--;
                        break;
                    }
                    l_sht = DAP_NEW_Z(dap_chain_tx_hash_processed_ht_t);
                    if (!l_sht) {
        log_it(L_CRITICAL, "Memory allocation error");
                        return NULL;
                    }
                    l_sht->hash = l_tx_hash;
                    HASH_ADD(hh, a_tx_hash_processed, hash, sizeof(dap_chain_hash_fast_t), l_sht);
                    l_tx_num++;
                } break;

                default: {
                    const char *l_type_str;
                    DAP_DATUM_TYPE_STR(l_datum->header.type_id, l_type_str);
                    dap_string_append_printf(l_str_out, "datum type %s\n", l_type_str);
                    } break;
                }
                l_datum_num++;
            }
        }
        a_chain->callback_atom_iter_delete(l_atom_iter);
        //total
        dap_string_append_printf(l_str_out,
                "---------------\ntokens: %zu\nemissions: %zu\ntransactions: %zu\ntotal datums: %zu", l_token_num,
                l_emission_num, l_tx_num, l_datum_num);

        // return total datums
        if(a_total_datums)
            *a_total_datums = l_datum_num;
        // delete hashes
        dap_tx_data_t *l_iter_current, *l_item_tmp;
        HASH_ITER(hh, l_tx_data_hash , l_iter_current, l_item_tmp)
        {
            HASH_DEL(l_tx_data_hash, l_iter_current);
            // delete datum
            DAP_DELETE(l_iter_current->datum);
            // delete struct
            DAP_DELETE(l_iter_current);
        }
        l_cell = l_cell->hh.next;
    } while (l_cell);

    // if no history
    if(!l_str_out->len)
        dap_string_append(l_str_out, "empty");
    char *l_ret_str = l_str_out ? dap_string_free(l_str_out, false) : NULL;
    return l_ret_str;
}

/**
 * @brief com_ledger
 * ledger command
 * @param a_argc
 * @param a_argv
 * @param a_arg_func
 * @param a_str_reply
 * @return int
 */
int com_ledger(int a_argc, char ** a_argv, char **a_str_reply)
{
    enum { CMD_NONE, CMD_LIST, CMD_LEDGER_HISTORY, CMD_TX_INFO };
    int arg_index = 1;
    const char *l_addr_base58 = NULL;
    const char *l_wallet_name = NULL;
    const char *l_net_str = NULL;
    const char *l_tx_hash_str = NULL;
    const char *l_hash_out_type = NULL;

    dap_chain_net_t * l_net = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    //switch ledger params list | tx | info
    int l_cmd = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "list", NULL)){
        l_cmd = CMD_LIST;
    } else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "tx", NULL)){
        l_cmd = CMD_LEDGER_HISTORY;
    } else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "info", NULL))
        l_cmd = CMD_TX_INFO;

    bool l_is_all = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-all", NULL);

    arg_index++;

    if(l_cmd == CMD_LEDGER_HISTORY) {
        dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-addr", &l_addr_base58);
        dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-w", &l_wallet_name);
        dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
        dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-tx", &l_tx_hash_str);
        bool l_unspent_flag = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-unspent", NULL);
        dap_chain_tx_hash_processed_ht_t *l_list_tx_hash_processd = NULL;

        if(!l_is_all && !l_addr_base58 && !l_wallet_name && !l_tx_hash_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "command 'tx' requires parameter '-all' or '-addr' or '-w' or '-tx'");
            return -1;
        }
        // Select chain network
        if(!l_net_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "command requires parameter '-net'");
            return -2;
        } else {
            if((l_net = dap_chain_net_by_name(l_net_str)) == NULL) { // Can't find such network
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "command requires parameter '-net' to be valid chain network name");
                return -3;
            }
        }

        dap_chain_hash_fast_t l_tx_hash;
        if(l_tx_hash_str) {
            if (dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash)) {
                l_tx_hash_str = NULL;
                dap_cli_server_cmd_set_reply_text(a_str_reply, "tx hash not recognized");
                return -1;
            }
        }
        
        dap_chain_addr_t *l_addr = NULL;
        // if need addr
        const char* l_sign_str = "";
        if(l_wallet_name || l_addr_base58) {
            if(l_wallet_name) {
                const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
                dap_chain_wallet_t * l_wallet = dap_chain_wallet_open(l_wallet_name, c_wallets_path);
                if(l_wallet) {
                    l_sign_str = dap_chain_wallet_check_bliss_sign(l_wallet);
                    l_addr = dap_chain_wallet_get_addr(l_wallet, l_net->pub.id);
                    dap_chain_wallet_close(l_wallet);
                }
            }
            if(!l_addr && l_addr_base58) {
                l_addr = dap_chain_addr_from_str(l_addr_base58);
            }
            if(!l_addr && !l_tx_hash_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "wallet address not recognized");
                return -1;
            }
        }
        dap_string_t *l_str_ret = dap_string_new(NULL);

        char *l_str_out = NULL;
        dap_ledger_t *l_ledger = dap_ledger_by_net_name(l_net_str);
        if(l_is_all) {
            size_t l_tx_count = dap_ledger_count(l_ledger), l_tx_count_spent_count = 0;
            if (!l_tx_count) {
                dap_string_append_printf(l_str_ret, "Network ledger %s contains no transactions.\n", l_ledger->net->pub.name);
            } else {
                dap_string_append_printf(l_str_ret, "There are %zu transactions in the network ledger %s:\n",
                                         l_tx_count, l_ledger->net->pub.name);
                dap_list_t *l_txs_list = dap_ledger_get_txs(l_ledger, l_tx_count, 1, true, l_unspent_flag);
                for (dap_list_t *iter = l_txs_list; iter; iter = dap_list_next(iter)) {
                    dap_chain_datum_tx_t *l_tx = iter->data;
                    dap_hash_fast_t l_tx_hash = { };
                    dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
                    s_dap_chain_datum_tx_out_data(l_tx, l_ledger, l_str_ret, l_hash_out_type, &l_tx_hash);
                }
                dap_list_free(l_txs_list);
            }
        } else {
            if(l_addr)
            {
                l_str_out = dap_ledger_token_tx_item_list(l_ledger, l_addr, l_hash_out_type, l_unspent_flag);
                char *l_addr_str = dap_chain_addr_to_str(l_addr);
                dap_string_append_printf(l_str_ret, "history for addr %s:\n%s\n", l_addr_str,
                        l_str_out ? l_str_out : " empty");
                DAP_DELETE(l_addr_str);
            } else if(l_tx_hash_str) {
                dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(l_ledger, &l_tx_hash);
                if (!l_tx && !l_unspent_flag) {
                    l_tx = dap_ledger_tx_spent_find_by_hash(l_ledger, &l_tx_hash);
                }
                if(l_tx) {
                    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
                    dap_hash_fast_t l_tx_hash = { };
                    dap_hash_fast(l_tx, l_tx_size, &l_tx_hash);
                    s_dap_chain_datum_tx_out_data(l_tx, l_ledger, l_str_ret, l_hash_out_type, &l_tx_hash);
                    dap_string_append_printf(l_str_ret, "history for tx hash %s:\n%s\n", l_tx_hash_str,
                            l_str_out ? l_str_out : " empty");
                } else {
                    dap_string_append_printf(l_str_ret, "There is not transaction %s in the network ledger\n",l_tx_hash_str);
                }
            }            
        }
        DAP_DELETE(l_str_out);
        DAP_DELETE(l_addr);
        s_dap_chain_tx_hash_processed_ht_free(&l_list_tx_hash_processd);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s\n%s", l_str_ret->str, l_sign_str);
        dap_string_free(l_str_ret, true);
        return 0;       
    }
    else if(l_cmd == CMD_LIST){
        enum {SUBCMD_NONE, SUBCMD_LIST_COIN, SUB_CMD_LIST_LEDGER_THRESHOLD, SUB_CMD_LIST_LEDGER_BALANCE, SUB_CMD_LIST_LEDGER_THRESHOLD_WITH_HASH};
        int l_sub_cmd = SUBCMD_NONE;
        dap_chain_hash_fast_t l_tx_threshold_hash;
        if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "coins", NULL ))
            l_sub_cmd = SUBCMD_LIST_COIN;
        if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "balance", NULL ))
            l_sub_cmd = SUB_CMD_LIST_LEDGER_BALANCE;
        if (dap_cli_server_cmd_find_option_val(a_argv, 2, a_argc, "threshold", NULL)){
            l_sub_cmd = SUB_CMD_LIST_LEDGER_THRESHOLD;
            const char* l_tx_threshold_hash_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, 3, a_argc, "-hash", &l_tx_threshold_hash_str);
            if (l_tx_threshold_hash_str){
                l_sub_cmd = SUB_CMD_LIST_LEDGER_THRESHOLD_WITH_HASH;
                if (dap_chain_hash_fast_from_str(l_tx_threshold_hash_str, &l_tx_threshold_hash)){
                    l_tx_hash_str = NULL;
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "tx threshold hash not recognized");
                    return -1;
                }
            }
        }
        if (l_sub_cmd == SUBCMD_NONE) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'list' requires subcommands 'coins' or 'threshold'");
            return -5;
        }
        dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
        if (l_net_str == NULL){
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'list' requires key -net");
            return -1;
        }
        dap_ledger_t *l_ledger = dap_ledger_by_net_name(l_net_str);
        if (l_ledger == NULL){
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't get ledger for net %s", l_net_str);
            return -2;
        }
        if (l_sub_cmd == SUB_CMD_LIST_LEDGER_THRESHOLD){
            dap_string_t *l_str_ret = dap_ledger_threshold_info(l_ledger);
            if (l_str_ret){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_ret->str);
                dap_string_free(l_str_ret, true);
            }

            return 0;
        }
        if (l_sub_cmd == SUB_CMD_LIST_LEDGER_THRESHOLD_WITH_HASH){
            dap_string_t *l_str_ret = dap_ledger_threshold_hash_info(l_ledger, &l_tx_threshold_hash);
            if (l_str_ret){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_ret->str);
                dap_string_free(l_str_ret, true);
            }

            return 0;
        }
        if (l_sub_cmd == SUB_CMD_LIST_LEDGER_BALANCE){
            dap_string_t *l_str_ret = dap_ledger_balance_info(l_ledger);
            if (l_str_ret){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_ret->str);
                dap_string_free(l_str_ret, true);
            }

            return 0;
        }
        dap_string_t *l_str_ret = dap_string_new("");
        dap_list_t *l_token_list = dap_ledger_token_info(l_ledger);
        dap_string_append_printf(l_str_ret, "Found %lu tokens in %s ledger\n", dap_list_length(l_token_list), l_net_str);
        for (dap_list_t *l_list = l_token_list; l_list; l_list = dap_list_next(l_list)) {
            dap_string_append(l_str_ret, (char *)l_list->data);
        }
        dap_list_free_full(l_token_list, NULL);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_ret->str);
        dap_string_free(l_str_ret, true);
        return 0;
    } else if (l_cmd == CMD_TX_INFO){
        //GET hash
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_tx_hash_str);
        //get net
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
        //get search type
        bool l_unspent_flag = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-unspent", NULL);
        //check input
        if (l_tx_hash_str == NULL){
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Subcommand 'info' requires key -hash");
            return -1;
        }
        if (l_net_str == NULL){
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Subcommand 'info' requires key -net");
            return -2;
        }
        dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
        if (!l_net) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find net %s", l_net_str);
            return -2;
        }
        dap_chain_hash_fast_t *l_tx_hash = DAP_NEW(dap_chain_hash_fast_t);
        if (dap_chain_hash_fast_from_str(l_tx_hash_str, l_tx_hash)) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't get hash_fast from %s, check that the hash is correct", l_tx_hash_str);
            return -4;
        }
        dap_chain_datum_tx_t *l_datum_tx = dap_chain_net_get_tx_by_hash(l_net, l_tx_hash,
                                                                        l_unspent_flag ? TX_SEARCH_TYPE_NET_UNSPENT : TX_SEARCH_TYPE_NET);
        if (l_datum_tx == NULL) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find datum for transaction hash %s in chains", l_tx_hash_str);
            return -5;
        }
        dap_string_t *l_str = dap_string_new("");
        if (!s_dap_chain_datum_tx_out_data(l_datum_tx, l_net->pub.ledger, l_str, l_hash_out_type, l_tx_hash))
            dap_string_append_printf(l_str, "Can't find transaction hash %s in ledger", l_tx_hash_str);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str->str);
        dap_string_free(l_str, true);
    }
    else{
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'ledger' requires parameter 'list' or 'tx' or 'info'");
        return -6;
    }
    return 0;
}


/**
 * @brief com_token
 * token command
 * @param a_argc
 * @param a_argv
 * @param a_arg_func
 * @param a_str_reply
 * @return int
 */
int com_token(int a_argc, char ** a_argv, char **a_str_reply)
{
    enum { CMD_NONE, CMD_LIST, CMD_INFO, CMD_TX };
    int arg_index = 1;
    const char *l_net_str = NULL;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if (!l_hash_out_type)
        l_hash_out_type = "hex";
    if (dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    // Select chain network
    if(!l_net_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "command requires parameter '-net'");
        return -2;
    } else {
        if((l_net = dap_chain_net_by_name(l_net_str)) == NULL) { // Can't find such network
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                    "command requires parameter '-net' to be valid chain network name");
            return -3;
        }
    }

    int l_cmd = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "list", NULL))
        l_cmd = CMD_LIST;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "info", NULL))
        l_cmd = CMD_INFO;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "tx", NULL))
            l_cmd = CMD_TX;
    // token list
    if(l_cmd == CMD_LIST) {
        dap_string_t *l_str_out = dap_string_new(NULL);
        size_t l_token_num_total = dap_db_net_history_token_list(l_net, NULL, l_hash_out_type, l_str_out);
        //total
        dap_string_append_printf(l_str_out, "---------------\ntokens: %zu\n", l_token_num_total);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_out->str);
        dap_string_free(l_str_out, true);
        return 0;
    }
    // token info
    else if(l_cmd == CMD_INFO) {
        const char *l_token_name_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-name", &l_token_name_str);
        if(!l_token_name_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "command requires parameter '-name' <token name>");
                return -4;
            }
        dap_string_t *l_str_out = dap_string_new(NULL);
        if(!dap_db_net_history_token_list(l_net, l_token_name_str, l_hash_out_type, l_str_out))
            dap_string_append_printf(l_str_out, "token '%s' not found\n", l_token_name_str);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_out->str);
        dap_string_free(l_str_out, true);
        return 0;
    }
    // command tx history
    else if(l_cmd == CMD_TX) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "The cellframe-node-cli token tx command is deprecated and no longer supported.\n");
        return 0;
#if 0
        dap_chain_tx_hash_processed_ht_t *l_list_tx_hash_processd = NULL;
        enum { SUBCMD_TX_NONE, SUBCMD_TX_ALL, SUBCMD_TX_ADDR };
        // find subcommand
        int l_subcmd = CMD_NONE;
        const char *l_addr_base58_str = NULL;
        const char *l_wallet_name = NULL;
        if(dap_cli_server_cmd_find_option_val(a_argv, 2, a_argc, "all", NULL))
            l_subcmd = SUBCMD_TX_ALL;
        else if(dap_cli_server_cmd_find_option_val(a_argv, 2, a_argc, "-addr", &l_addr_base58_str))
            l_subcmd = SUBCMD_TX_ADDR;
        else if(dap_cli_server_cmd_find_option_val(a_argv, 2, a_argc, "-w", &l_wallet_name))
            l_subcmd = SUBCMD_TX_ADDR;

        const char *l_token_name_str = NULL;
        const char *l_page_start_str = NULL;
        const char *l_page_size_str = NULL;
        const char *l_page_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-name", &l_token_name_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-page_start", &l_page_start_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-page_size", &l_page_size_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-page", &l_page_str);
        if(!l_token_name_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "command requires parameter '-name' <token name>");
            return -4;
        }
        long l_page_start = -1;// not used if =-1
        long l_page_size = 10;
        long l_page = 2;
        long l_cur_datum = 0;
        if(l_page_start_str)
            l_page_start = strtol(l_page_start_str, NULL, 10);
        if(l_page_size_str) {
            l_page_size = strtol(l_page_size_str, NULL, 10);
            if(l_page_size < 1)
                l_page_size = 1;
        }
        if(l_page_str) {
            l_page = strtol(l_page_str, NULL, 10);
            if(l_page < 1)
                l_page = 1;
        }

        // tx all
        if(l_subcmd == SUBCMD_TX_ALL) {
            dap_string_t *l_str_out = dap_string_new(NULL);
            // get first chain
            void *l_chain_tmp = (void*) 0x1;
            dap_chain_t *l_chain_cur = dap_chain_enum(&l_chain_tmp);
            while(l_chain_cur) {
                // only selected net
                if(l_net->pub.id.uint64 == l_chain_cur->net_id.uint64) {
                    long l_chain_datum = l_cur_datum;
                    dap_ledger_t *l_ledger = dap_ledger_by_net_name(l_net_str);
                    char *l_datum_list_str = dap_db_history_filter(l_chain_cur, l_ledger, l_token_name_str, NULL,
                                                                   l_hash_out_type, l_page_start * l_page_size, (l_page_start+l_page)*l_page_size, &l_chain_datum, l_list_tx_hash_processd);
                    if(l_datum_list_str) {
                        l_cur_datum += l_chain_datum;
                        dap_string_append_printf(l_str_out, "Chain: %s\n", l_chain_cur->name);
                        dap_string_append_printf(l_str_out, "%s\n\n", l_datum_list_str);
                        DAP_DELETE(l_datum_list_str);
                    }
                }
                // next chain
                dap_chain_enum_unlock();
                l_chain_cur = dap_chain_enum(&l_chain_tmp);
            }
            dap_chain_enum_unlock();
            s_dap_chain_tx_hash_processed_ht_free(&l_list_tx_hash_processd);
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_out->str);
            dap_string_free(l_str_out, true);
            return 0;
        }
            // tx -addr or tx -wallet
        else if(l_subcmd == SUBCMD_TX_ADDR) {
            // parse addr from -addr <addr> or -wallet <wallet>
            dap_chain_addr_t *l_addr_base58 = NULL;
            if(l_addr_base58_str) {
                //l_addr_base58 = dap_strdup(l_addr_base58_str);
                l_addr_base58 = dap_chain_addr_from_str(l_addr_base58_str);
            }
            else if(l_wallet_name) {
                const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
                dap_chain_wallet_t * l_wallet = dap_chain_wallet_open(l_wallet_name, c_wallets_path);
                if(l_wallet) {
                    dap_chain_addr_t *l_addr_tmp = (dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet,
                                                                                                  l_net->pub.id);
                    l_addr_base58 = DAP_NEW_SIZE(dap_chain_addr_t, sizeof(dap_chain_addr_t));
                    memcpy(l_addr_base58, l_addr_tmp, sizeof(dap_chain_addr_t));
                    dap_chain_wallet_close(l_wallet);
                    char *ffl_addr_base58 = dap_chain_addr_to_str(l_addr_base58);
                    ffl_addr_base58 = 0;
                }
                else {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "wallet '%s' not found", l_wallet_name);
                    return -2;
                }
            }
            if(!l_addr_base58) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "address not recognized");
                return -3;
            }

            dap_string_t *l_str_out = dap_string_new(NULL);
            // get first chain
            void *l_chain_tmp = (void*) 0x1;
            dap_chain_t *l_chain_cur = dap_chain_enum(&l_chain_tmp);
            while(l_chain_cur) {
                // only selected net
                if(l_net->pub.id.uint64 == l_chain_cur->net_id.uint64) {
                    long l_chain_datum = l_cur_datum;
                    char *l_datum_list_str = dap_db_history_addr(l_addr_base58, l_chain_cur, l_hash_out_type);
                    if(l_datum_list_str) {
                        l_cur_datum += l_chain_datum;
                        dap_string_append_printf(l_str_out, "Chain: %s\n", l_chain_cur->name);
                        dap_string_append_printf(l_str_out, "%s\n\n", l_datum_list_str);
                        DAP_DELETE(l_datum_list_str);
                    }
                }
                // next chain
                dap_chain_enum_unlock();
                l_chain_cur = dap_chain_enum(&l_chain_tmp);
            }
            dap_chain_enum_unlock();
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_out->str);
            dap_string_free(l_str_out, true);
            DAP_DELETE(l_addr_base58);
            return 0;

        }
        else{
            dap_cli_server_cmd_set_reply_text(a_str_reply, "not found parameter '-all', '-wallet' or '-addr'");
            return -1;
        }
#endif
    }

    dap_cli_server_cmd_set_reply_text(a_str_reply, "unknown command code %d", l_cmd);
    return -5;
}

/* Decree section */

/**
 * @brief
 * sign data (datum_decree) by certificates (1 or more)
 * successful count of signes return in l_sign_counter
 * @param l_certs - array with certificates loaded from dcert file
 * @param l_datum_token - updated pointer for l_datum_token variable after realloc
 * @param l_certs_count - count of certificate
 * @param l_datum_data_offset - offset of datum
 * @param l_sign_counter - counter of successful data signing operation
 * @return dap_chain_datum_token_t*
 */
static dap_chain_datum_anchor_t * s_sign_anchor_in_cycle(dap_cert_t ** a_certs, dap_chain_datum_anchor_t *a_datum_anchor,
                    size_t a_certs_count, size_t *a_total_sign_count)
{
    size_t l_cur_sign_offset = a_datum_anchor->header.data_size + a_datum_anchor->header.signs_size;
    size_t l_total_signs_size = a_datum_anchor->header.signs_size, l_total_sign_count = 0;

    for(size_t i = 0; i < a_certs_count; i++)
    {
        dap_sign_t * l_sign = dap_cert_sign(a_certs[i],  a_datum_anchor,
           sizeof(dap_chain_datum_anchor_t) + a_datum_anchor->header.data_size, 0);

        if (l_sign) {
            size_t l_sign_size = dap_sign_get_size(l_sign);
            a_datum_anchor = DAP_REALLOC(a_datum_anchor, sizeof(dap_chain_datum_anchor_t) + l_cur_sign_offset + l_sign_size);
            memcpy((byte_t*)a_datum_anchor->data_n_sign + l_cur_sign_offset, l_sign, l_sign_size);
            l_total_signs_size += l_sign_size;
            l_cur_sign_offset += l_sign_size;
            a_datum_anchor->header.signs_size = l_total_signs_size;
            DAP_DELETE(l_sign);
            log_it(L_DEBUG,"<-- Signed with '%s'", a_certs[i]->name);
            l_total_sign_count++;
        }
    }

    *a_total_sign_count = l_total_sign_count;
    return a_datum_anchor;
}

// Decree commands handlers
int cmd_decree(int a_argc, char **a_argv, char ** a_str_reply)
{
    enum { CMD_NONE=0, CMD_CREATE, CMD_SIGN, CMD_ANCHOR, CMD_FIND, CMD_INFO };
    enum { TYPE_NONE=0, TYPE_COMMON, TYPE_SERVICE};
    enum { SUBTYPE_NONE=0, SUBTYPE_FEE, SUBTYPE_OWNERS, SUBTYPE_MIN_OWNERS, SUBTYPE_IP_BAN};
    int arg_index = 1;
    const char *l_net_str = NULL;
    const char * l_chain_str = NULL;
    const char * l_decree_chain_str = NULL;
    const char * l_certs_str = NULL;
    dap_cert_t ** l_certs = NULL;
    size_t l_certs_count = 0;
    dap_chain_net_t * l_net = NULL;
    dap_chain_t * l_chain = NULL;
    dap_chain_t * l_decree_chain = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    // Select chain network
    if(!l_net_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "command requires parameter '-net'");
        return -2;
    } else {
        if((l_net = dap_chain_net_by_name(l_net_str)) == NULL) { // Can't find such network
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                    "command requires parameter '-net' to be valid chain network name");
            return -3;
        }
    }

    int l_cmd = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "create", NULL))
        l_cmd = CMD_CREATE;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "sign", NULL))
        l_cmd = CMD_SIGN;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "anchor", NULL))
        l_cmd = CMD_ANCHOR;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "find", NULL))
        l_cmd = CMD_FIND;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "info", NULL))
        l_cmd = CMD_INFO;

    if (l_cmd != CMD_FIND && l_cmd != CMD_INFO) {
        // Public certifiacte of condition owner
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-certs", &l_certs_str);
        if (!l_certs_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "decree create requires parameter '-certs'");
            return -106;
        }
        dap_cert_parse_str_list(l_certs_str, &l_certs, &l_certs_count);
    }

    switch (l_cmd)
    {
    case CMD_CREATE:{
        if(!l_certs_count) {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                    "decree create command requres at least one valid certificate to sign the decree");
            return -106;
        }
        int l_type = TYPE_NONE;
        if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "common", NULL))
            l_type = TYPE_COMMON;
        else if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "service", NULL))
            l_type = TYPE_SERVICE;

        dap_chain_datum_decree_t *l_datum_decree = NULL;

        if (l_type == TYPE_COMMON){
            // Common decree create
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);

            // Search chain
            if(l_chain_str) {
                l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
                if (l_chain == NULL) {
                    char l_str_to_reply_chain[500] = {0};
                    char *l_str_to_reply = NULL;
                    sprintf(l_str_to_reply_chain, "%s requires parameter '-chain' to be valid chain name in chain net %s. Current chain %s is not valid\n",
                                                    a_argv[0], l_net_str, l_chain_str);
                    l_str_to_reply = dap_strcat2(l_str_to_reply,l_str_to_reply_chain);
                    dap_chain_t * l_chain;
                    l_str_to_reply = dap_strcat2(l_str_to_reply,"\nAvailable chain with decree support:\n");
                    l_chain = dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE);
                    l_str_to_reply = dap_strcat2(l_str_to_reply,"\t");
                    l_str_to_reply = dap_strcat2(l_str_to_reply,l_chain->name);
                    l_str_to_reply = dap_strcat2(l_str_to_reply,"\n");
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_to_reply);
                    return -103;
                } else if (l_chain != dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE)){ // check chain to support decree
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Chain %s don't support decree", l_chain->name);
                    return -104;
                }
            }else if((l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE)) == NULL) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find chain with decree support.");
                return -105;
            }

            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-decree_chain", &l_decree_chain_str);

            // Search chain
            if(l_decree_chain_str) {
                l_decree_chain = dap_chain_net_get_chain_by_name(l_net, l_decree_chain_str);
                if (l_decree_chain == NULL) {
                    char l_str_to_reply_chain[500] = {0};
                    char *l_str_to_reply = NULL;
                    sprintf(l_str_to_reply_chain, "%s requires parameter '-decree_chain' to be valid chain name in chain net %s. Current chain %s is not valid\n",
                                                    a_argv[0], l_net_str, l_chain_str);
                    l_str_to_reply = dap_strcat2(l_str_to_reply,l_str_to_reply_chain);
                    dap_chain_t * l_chain;
                    dap_chain_net_t * l_chain_net = l_net;
                    l_str_to_reply = dap_strcat2(l_str_to_reply,"\nAvailable chains:\n");
                    DL_FOREACH(l_chain_net->pub.chains, l_chain) {
                            l_str_to_reply = dap_strcat2(l_str_to_reply,"\t");
                            l_str_to_reply = dap_strcat2(l_str_to_reply,l_chain->name);
                            l_str_to_reply = dap_strcat2(l_str_to_reply,"\n");
                    }
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_to_reply);
                    return -103;
                }
            }else {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "decree requires parameter -decree_chain.");
                return -105;
            }

            dap_tsd_t *l_tsd = NULL;
            dap_cert_t **l_new_certs = NULL;
            size_t l_new_certs_count = 0, l_total_tsd_size = 0;
            dap_list_t *l_tsd_list = NULL;

            int l_subtype = SUBTYPE_NONE;
            const char *l_param_value_str = NULL;
            const char *l_param_addr_str = NULL;
            if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_param_value_str)){
                l_subtype = SUBTYPE_FEE;
                if (!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-to_addr", &l_param_addr_str)){
                    if(!l_net->pub.decree->fee_addr)
                    {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Net fee add needed. Use -to_addr parameter");
                        return -111;
                    }
                }else{
                    l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(dap_chain_addr_t);
                    l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
                    if (!l_tsd) {
                        log_it(L_CRITICAL, "Memory allocation error");
                        dap_list_free_full(l_tsd_list, NULL);
                        return -1;
                    }
                    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE_WALLET;
                    l_tsd->size = sizeof(dap_chain_addr_t);
                    dap_chain_addr_t *l_addr = dap_chain_addr_from_str(l_param_addr_str);
                    memcpy(l_tsd->data, l_addr, sizeof(dap_chain_addr_t));
                    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
                }

                l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(uint256_t);
                l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
                if (!l_tsd) {
                    log_it(L_CRITICAL, "Memory allocation error");
                    dap_list_free_full(l_tsd_list, NULL);
                    return -1;
                }
                l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE;
                l_tsd->size = sizeof(uint256_t);
                *(uint256_t*)(l_tsd->data) = dap_uint256_scan_uninteger(l_param_value_str);
                l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
            }else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-new_certs", &l_param_value_str)){
                l_subtype = SUBTYPE_OWNERS;
                dap_cert_parse_str_list(l_param_value_str, &l_new_certs, &l_new_certs_count);

                dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
                uint16_t l_min_signs = l_net->pub.decree->min_num_of_owners;
                if (l_new_certs_count < l_min_signs) {
                    log_it(L_WARNING,"Number of new certificates is less than minimum owner number.");
                    return -106;
                }

                size_t l_failed_certs = 0;
                for (size_t i=0;i<l_new_certs_count;i++){
                    dap_pkey_t *l_pkey = dap_cert_to_pkey(l_new_certs[i]);
                    if(!l_pkey)
                    {
                        log_it(L_WARNING,"New cert [%zu] have no public key.", i);
                        l_failed_certs++;
                        continue;
                    }
                    l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER, l_pkey, sizeof(dap_pkey_t) + (size_t)l_pkey->header.size);
                    DAP_DELETE(l_pkey);
                    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
                    l_total_tsd_size += sizeof(dap_tsd_t) + (size_t)l_tsd->size;
                }
                if(l_failed_certs)
                {
                    dap_list_free_full(l_tsd_list, NULL);
                    return -108;
                }
            }else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-signs_verify", &l_param_value_str)) {
                l_subtype = SUBTYPE_MIN_OWNERS;
                uint256_t l_new_num_of_owners = dap_uint256_scan_uninteger(l_param_value_str);
                if (IS_ZERO_256(l_new_num_of_owners)) {
                    log_it(L_WARNING, "The minimum number of owners can't be zero");
                    dap_list_free_full(l_tsd_list, NULL);
                    return -112;
                }
                dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
                uint256_t l_owners = GET_256_FROM_64(l_net->pub.decree->num_of_owners);
                if (compare256(l_new_num_of_owners, l_owners) > 0) {
                    log_it(L_WARNING, "The minimum number of owners is greater than the total number of owners.");
                    dap_list_free_full(l_tsd_list, NULL);
                    return -110;
                }

                l_total_tsd_size = sizeof(dap_tsd_t) + sizeof(uint256_t);
                l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
                if (!l_tsd) {
                    log_it(L_CRITICAL, "Memory allocation error");
                    dap_list_free_full(l_tsd_list, NULL);
                    return -1;
                }
                l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER;
                l_tsd->size = sizeof(uint256_t);
                *(uint256_t *) (l_tsd->data) = l_new_num_of_owners;
                l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
            } else{
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Decree subtype fail.");
                return -111;
            }

            if (l_subtype == DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS ||
                l_subtype == DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS_MIN)
            {
                if (l_decree_chain->id.uint64 != l_chain->id.uint64){
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Decree subtype %s not suppurted by chain %s",
                                                      dap_chain_datum_decree_subtype_to_str(l_subtype), l_decree_chain_str);
                    return -107;
                }
            } else if (l_decree_chain->id.uint64 == l_chain->id.uint64){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Decree subtype %s not suppurted by chain %s",
                                                  dap_chain_datum_decree_subtype_to_str(l_subtype), l_decree_chain_str);
                return -107;
            }

            l_datum_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, sizeof(dap_chain_datum_decree_t) + l_total_tsd_size);
            l_datum_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
            l_datum_decree->header.ts_created = dap_time_now();
            l_datum_decree->header.type = l_type;
            l_datum_decree->header.common_decree_params.net_id = dap_chain_net_id_by_name(l_net_str);
            l_datum_decree->header.common_decree_params.chain_id = l_decree_chain->id;
            l_datum_decree->header.common_decree_params.cell_id = *dap_chain_net_get_cur_cell(l_net);
            l_datum_decree->header.sub_type = l_subtype;
            l_datum_decree->header.data_size = l_total_tsd_size;
            l_datum_decree->header.signs_size = 0;

            size_t l_data_tsd_offset = 0;
            for ( dap_list_t* l_iter=dap_list_first(l_tsd_list); l_iter; l_iter=l_iter->next){
                dap_tsd_t * l_b_tsd = (dap_tsd_t *) l_iter->data;
                size_t l_tsd_size = dap_tsd_size(l_b_tsd);
                memcpy((byte_t*)l_datum_decree->data_n_signs + l_data_tsd_offset, l_b_tsd, l_tsd_size);
                l_data_tsd_offset += l_tsd_size;
            }
            dap_list_free_full(l_tsd_list, NULL);

        }else if (l_type == TYPE_SERVICE) {

        }else{
            dap_cli_server_cmd_set_reply_text(a_str_reply, "not found decree type (common or service)");
            return -107;
        }

        // Sign decree
        size_t l_total_signs_success = 0;
        if (l_certs_count)
            l_datum_decree = dap_chain_datum_decree_in_cycle(l_certs, l_datum_decree, l_certs_count, &l_total_signs_success);

        if (!l_datum_decree || l_total_signs_success == 0){
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Decree creation failed. Successful count of certificate signing is 0");
                return -108;
        }

        // Create datum
        dap_chain_datum_t * l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE,
                                                             l_datum_decree,
                                                             sizeof(*l_datum_decree) + l_datum_decree->header.data_size +
                                                             l_datum_decree->header.signs_size);
        DAP_DELETE(l_datum_decree);
        char *l_key_str_out = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
        DAP_DELETE(l_datum);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Datum %s is%s placed in datum pool",
                                          l_key_str_out ? l_key_str_out : "",
                                          l_key_str_out ? "" : " not");
        break;
    }
    case CMD_SIGN:{
        if(!l_certs_count) {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                    "decree sign command requres at least one valid certificate to sign");
            return -106;
        }

        const char * l_datum_hash_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-datum", &l_datum_hash_str);
        if(l_datum_hash_str) {
            char * l_datum_hash_hex_str = NULL;
            char * l_datum_hash_base58_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);
            // Search chain
            if(l_chain_str) {
                l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
                if (l_chain == NULL) {
                    char l_str_to_reply_chain[500] = {0};
                    char *l_str_to_reply = NULL;
                    sprintf(l_str_to_reply_chain, "%s requires parameter '-chain' to be valid chain name in chain net %s. Current chain %s is not valid\n",
                                                    a_argv[0], l_net_str, l_chain_str);
                    l_str_to_reply = dap_strcat2(l_str_to_reply,l_str_to_reply_chain);
                    dap_chain_t * l_chain;
                    l_str_to_reply = dap_strcat2(l_str_to_reply,"\nAvailable chain with decree support:\n");
                    l_chain = dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE);
                    l_str_to_reply = dap_strcat2(l_str_to_reply,"\t");
                    l_str_to_reply = dap_strcat2(l_str_to_reply,l_chain->name);
                    l_str_to_reply = dap_strcat2(l_str_to_reply,"\n");
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_to_reply);
                    return -103;
                } else if (l_chain != dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE)){ // check chain to support decree
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Chain %s don't support decree", l_chain->name);
                    return -104;
                }
            }else if((l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE)) == NULL) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find chain with decree support.");
                return -105;
            }

            char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_new(l_chain);
            if(!l_gdb_group_mempool) {
                l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_by_chain_type(l_net, CHAIN_TYPE_DECREE);
            }
            // datum hash may be in hex or base58 format
            if(!dap_strncmp(l_datum_hash_str, "0x", 2) || !dap_strncmp(l_datum_hash_str, "0X", 2)) {
                l_datum_hash_hex_str = dap_strdup(l_datum_hash_str);
                l_datum_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_datum_hash_str);
            } else {
                l_datum_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_datum_hash_str);
                l_datum_hash_base58_str = dap_strdup(l_datum_hash_str);
            }

            const char *l_datum_hash_out_str;
            if(!dap_strcmp(l_hash_out_type,"hex"))
                l_datum_hash_out_str = l_datum_hash_hex_str;
            else
                l_datum_hash_out_str = l_datum_hash_base58_str;

            log_it(L_DEBUG, "Requested to sign decree creation %s in gdb://%s with certs %s",
                    l_gdb_group_mempool, l_datum_hash_hex_str, l_certs_str);

            dap_chain_datum_t * l_datum = NULL;
            size_t l_datum_size = 0;
            if((l_datum = (dap_chain_datum_t*) dap_global_db_get_sync(l_gdb_group_mempool,
                    l_datum_hash_hex_str, &l_datum_size, NULL, NULL )) != NULL) {
                // Check if its decree creation
                if(l_datum->header.type_id == DAP_CHAIN_DATUM_DECREE) {
                    dap_chain_datum_decree_t *l_datum_decree = DAP_DUP_SIZE(l_datum->data, l_datum->header.data_size);    // for realloc
                    DAP_DELETE(l_datum);

                    // Sign decree
                    size_t l_total_signs_success = 0;
                    if (l_certs_count)
                        l_datum_decree = dap_chain_datum_decree_in_cycle(l_certs, l_datum_decree, l_certs_count, &l_total_signs_success);

                    if (!l_datum_decree || l_total_signs_success == 0){
                        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                    "Decree creation failed. Successful count of certificate signing is 0");
                            return -108;
                    }
                    size_t l_decree_size = dap_chain_datum_decree_get_size(l_datum_decree);
                    dap_chain_datum_t * l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE,
                                                                         l_datum_decree, l_decree_size);
                    DAP_DELETE(l_datum_decree);

                    char *l_key_str_out = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
                    DAP_DELETE(l_datum);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Datum %s is%s placed in datum pool",
                                                      l_key_str_out ? l_key_str_out : "",
                                                      l_key_str_out ? "" : " not");

                    }else{
                    dap_cli_server_cmd_set_reply_text(a_str_reply,
                            "Error! Wrong datum type. decree sign only decree datum");
                    return -61;
                }
            }else{
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "decree sign can't find datum with %s hash in the mempool of %s:%s",l_datum_hash_out_str,l_net? l_net->pub.name: "<undefined>",
                        l_chain?l_chain->name:"<undefined>");
                return -5;
            }
            DAP_DELETE(l_datum_hash_hex_str);
            DAP_DELETE(l_datum_hash_base58_str);
        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "decree sign need -datum <datum hash> argument");
            return -2;
        }
        break;
    }
    case CMD_ANCHOR:{
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);

        // Search chain
        if(l_chain_str) {
            l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
            if (l_chain == NULL) {
                char l_str_to_reply_chain[500] = {0};
                char *l_str_to_reply = NULL;
                sprintf(l_str_to_reply_chain, "%s requires parameter '-chain' to be valid chain name in chain net %s. Current chain %s is not valid\n",
                                                a_argv[0], l_net_str, l_chain_str);
                l_str_to_reply = dap_strcat2(l_str_to_reply,l_str_to_reply_chain);
                dap_chain_t * l_chain;
                l_str_to_reply = dap_strcat2(l_str_to_reply,"\nAvailable chain with anchor support:\n");
                l_chain = dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_ANCHOR);
                l_str_to_reply = dap_strcat2(l_str_to_reply,"\t");
                l_str_to_reply = dap_strcat2(l_str_to_reply,l_chain->name);
                l_str_to_reply = dap_strcat2(l_str_to_reply,"\n");
                dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_to_reply);
                return -103;
            } else if (l_chain != dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_ANCHOR)){ // check chain to support decree
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Chain %s don't support decree", l_chain->name);
                return -104;
            }
        }else if((l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_ANCHOR)) == NULL) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find chain with default anchor support.");
            return -105;
        }

        dap_chain_datum_anchor_t *l_datum_anchor = NULL;
        dap_hash_fast_t l_hash = {};
        const char * l_datum_hash_str = NULL;
        if (!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-datum", &l_datum_hash_str))
        {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Anchor creation failed. Cmd decree create anchor must contain -datum parameter.");
                return -107;
        }
        if(l_datum_hash_str) {
            dap_chain_hash_fast_from_str(l_datum_hash_str, &l_hash);
        }

        // Pack data into TSD
        dap_tsd_t *l_tsd = NULL;
        l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_ANCHOR_TSD_TYPE_DECREE_HASH, &l_hash, sizeof(dap_hash_fast_t));
        if(!l_tsd)
        {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Anchor creation failed. Memory allocation fail.");
                return -107;
        }

        // Create anchor datum
        l_datum_anchor = DAP_NEW_Z_SIZE(dap_chain_datum_anchor_t, sizeof(dap_chain_datum_anchor_t) + dap_tsd_size(l_tsd));
        l_datum_anchor->header.data_size = dap_tsd_size(l_tsd);
        l_datum_anchor->header.ts_created = dap_time_now();
        memcpy(l_datum_anchor->data_n_sign, l_tsd, dap_tsd_size(l_tsd));

        DAP_DEL_Z(l_tsd);

        // Sign anchor
        size_t l_total_signs_success = 0;
        if (l_certs_count)
            l_datum_anchor = s_sign_anchor_in_cycle(l_certs, l_datum_anchor, l_certs_count, &l_total_signs_success);

        if (!l_datum_anchor || l_total_signs_success == 0){
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Anchor creation failed. Successful count of certificate signing is 0");
                return -108;
        }

        // Create datum
        dap_chain_datum_t * l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_ANCHOR,
                                                             l_datum_anchor,
                                                             sizeof(*l_datum_anchor) + l_datum_anchor->header.data_size +
                                                             l_datum_anchor->header.signs_size);
        DAP_DELETE(l_datum_anchor);
        char *l_key_str_out = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
        DAP_DELETE(l_datum);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Datum %s is%s placed in datum pool",
                                          l_key_str_out ? l_key_str_out : "",
                                          l_key_str_out ? "" : " not");
        break;
    }
    case CMD_FIND: {
        const char *l_hash_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_hash_str);
        if (!l_hash_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'decree find' requiers parameter '-hash'");
            return -110;
        }
        dap_hash_fast_t l_datum_hash;
        if (dap_chain_hash_fast_from_hex_str(l_hash_str, &l_datum_hash) &&
                dap_chain_hash_fast_from_base58_str(l_hash_str, &l_datum_hash)) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't convert '-hash' parameter to numeric value");
            return -111;
        }
        bool l_applied = false;
        dap_chain_datum_decree_t *l_decree = dap_chain_net_decree_get_by_hash(&l_datum_hash, &l_applied);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified decree is %s in decrees hash-table",
                                          l_decree ? (l_applied ? "applied" : "not applied") : "not found");
    } break;
    case CMD_INFO: {
        dap_string_t *l_str_owner_pkey = dap_string_new("");
        int i = 1;
        for (dap_list_t *l_current_pkey = l_net->pub.decree->pkeys; l_current_pkey; l_current_pkey = l_current_pkey->next){
            dap_pkey_t *l_pkey = (dap_pkey_t*)(l_current_pkey->data);
            dap_hash_fast_t l_pkey_hash = {0};
            dap_pkey_get_hash(l_pkey, &l_pkey_hash);
            char *l_pkey_hash_str = dap_hash_fast_to_str_new(&l_pkey_hash);
            dap_string_append_printf(l_str_owner_pkey, "\t%d) %s\n", i, l_pkey_hash_str);
            i++;
            DAP_DELETE(l_pkey_hash_str);
        }
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Decree info:\n"
                                                       "\tOwners: %d\n"
                                                       "\t=====================================================================\n"
                                                       "%s"
                                                       "\t=====================================================================\n"
                                                       "\tMin owners for apply decree: %d\n",
                                          l_net->pub.decree->num_of_owners, l_str_owner_pkey->str,
                                          l_net->pub.decree->min_num_of_owners);
        dap_string_free(l_str_owner_pkey, true);
    } break;
    default:
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Not found decree action. Use create, sign, anchor or find parameter");
        return -1;
    }

    return 0;
}
