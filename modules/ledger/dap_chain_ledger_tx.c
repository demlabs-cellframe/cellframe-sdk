 
/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2024
 * All rights reserved.

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
#include "dap_chain_ledger_pvt.h"
#include "dap_notify_srv.h"

#define LOG_TAG "dap_ledger_tx"

typedef struct dap_ledger_verificator {
    int subtype;    // hash key
    dap_ledger_verificator_callback_t callback;
    dap_ledger_updater_callback_t callback_added;
    dap_ledger_delete_callback_t callback_deleted;
    UT_hash_handle hh;
} dap_ledger_verificator_t;

typedef struct dap_chain_ledger_votings_callbacks {
    dap_ledger_voting_callback_t voting_callback;
    dap_ledger_voting_delete_callback_t voting_delete_callback;
} dap_chain_ledger_votings_callbacks_t;

static dap_ledger_verificator_t *s_verificators;
static pthread_rwlock_t s_verificators_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static dap_chain_ledger_votings_callbacks_t s_voting_callbacks;
static dap_ledger_tax_callback_t s_tax_callback = NULL;

typedef struct dap_ledger_tokenizer {
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t sum;
    UT_hash_handle hh;
} dap_ledger_tokenizer_t;

typedef struct dap_ledger_tx_bound {
    uint8_t type;
    uint16_t prev_out_idx;
    uint256_t value;
    union {
        dap_ledger_token_item_t *token_item;    // For current_supply update on emissions
        dap_chain_tx_out_cond_t *cond;          // For conditional output
        struct {
            char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
            dap_chain_addr_t addr_from;
        } in;
    };
    union {
        dap_ledger_tx_item_t *prev_item;        // For not emission TX
        dap_ledger_token_emission_item_t *emission_item;
        dap_ledger_stake_lock_item_t *stake_lock_item;
        dap_ledger_reward_key_t reward_key;
    };
} dap_ledger_tx_bound_t;

typedef struct dap_ledger_cache_item {
    dap_chain_hash_fast_t *hash;
    bool found;
} dap_ledger_cache_item_t;

typedef struct dap_ledger_cache_str_item {
    char *key;
    bool found;
} dap_ledger_cache_str_item_t;

typedef struct dap_ledger_tx_notifier {
    dap_ledger_tx_add_notify_t callback;
    void *arg;
} dap_ledger_tx_notifier_t;

typedef struct dap_ledger_bridged_tx_notifier {
    dap_ledger_bridged_tx_notify_t callback;
    void *arg;
} dap_ledger_bridged_tx_notifier_t;

static dap_ledger_tx_item_t *s_tx_item_find_by_addr(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr, const char * a_token, dap_chain_hash_fast_t *a_tx_first_hash);
static bool s_ledger_tx_hash_is_used_out_item(dap_ledger_tx_item_t *a_item, int a_idx_out, dap_hash_fast_t *a_out_spender_hash);
static dap_ledger_stake_lock_item_t *s_emissions_for_stake_lock_item_find(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_token_emission_hash);

static dap_chain_datum_tx_t *s_tx_find_by_hash(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_tx_hash, dap_ledger_tx_item_t **a_item_out, bool a_unspent_only);
static struct json_object *s_wallet_info_json_collect(dap_ledger_t *a_ledger, dap_ledger_wallet_balance_t* a_bal);

static void s_ledger_stake_lock_cache_update(dap_ledger_t *a_ledger, dap_ledger_stake_lock_item_t *a_stake_lock_item);

static int s_sort_ledger_tx_item(dap_ledger_tx_item_t *a, dap_ledger_tx_item_t *b)
{
    if (a->cache_data.ts_created < b->cache_data.ts_created)
        return -1;
    if (a->cache_data.ts_created == b->cache_data.ts_created)
        return 0;
    return 1;
}

/**
 * @brief s_load_cache_gdb_loaded_txs_callback
 * @param a_global_db_context
 * @param a_rc
 * @param a_group
 * @param a_key
 * @param a_values_total
 * @param a_values_shift
 * @param a_values_count
 * @param a_values
 * @param a_arg
 */
static bool s_load_cache_gdb_loaded_txs_callback(dap_global_db_instance_t *a_dbi,
                                                 int a_rc, const char *a_group,
                                                 const size_t a_values_total, const size_t a_values_count,
                                                 dap_global_db_obj_t *a_values, void *a_arg)
{
    dap_ledger_t * l_ledger = (dap_ledger_t*) a_arg;
    dap_ledger_private_t * l_ledger_pvt = PVT(l_ledger);
    for (size_t i = 0; i < a_values_count; i++) {
        dap_ledger_tx_item_t *l_tx_item = DAP_NEW_Z(dap_ledger_tx_item_t);
        if ( !l_tx_item ) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return false;
        }
        dap_chain_hash_fast_from_str(a_values[i].key, &l_tx_item->tx_hash_fast);
        l_tx_item->tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, a_values[i].value_len - sizeof(l_tx_item->cache_data));
        if ( !l_tx_item->tx ) {
            DAP_DELETE(l_tx_item);
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return false;
        }
        memcpy(&l_tx_item->cache_data, a_values[i].value, sizeof(l_tx_item->cache_data));
        memcpy(l_tx_item->tx, a_values[i].value + sizeof(l_tx_item->cache_data), a_values[i].value_len - sizeof(l_tx_item->cache_data));
        l_tx_item->ts_added = dap_nanotime_now();
        HASH_ADD(hh, l_ledger_pvt->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_tx_item);
    }
    HASH_SORT(l_ledger_pvt->ledger_items, s_sort_ledger_tx_item);

    char* l_gdb_group = dap_ledger_get_gdb_group(l_ledger, DAP_LEDGER_BALANCES_STR);
    dap_global_db_get_all(l_gdb_group, 0, dap_ledger_pvt_cache_gdb_load_balances_callback, l_ledger);
    DAP_DELETE(l_gdb_group);
    return true;
}


bool dap_ledger_pvt_cache_gdb_load_stake_lock_callback(dap_global_db_instance_t *a_dbi,
                                                        int a_rc, const char *a_group,
                                                        const size_t a_values_total, const size_t a_values_count,
                                                        dap_global_db_obj_t *a_values, void *a_arg)
{
    dap_ledger_t *l_ledger = (dap_ledger_t *) a_arg;
    dap_ledger_private_t *l_ledger_pvt = PVT(l_ledger);

    for (size_t i = 0; i < a_values_count; i++) {
        if (a_values[i].value_len != sizeof(dap_hash_fast_t))
            continue;
        dap_ledger_stake_lock_item_t *l_new_stake_lock_emission = DAP_NEW(dap_ledger_stake_lock_item_t);
        if (!l_new_stake_lock_emission) {
            debug_if(g_debug_ledger, L_ERROR, "Error: memory allocation when try adding item 'dap_ledger_stake_lock_item_t' to hash-table");
            continue;
        }
        dap_chain_hash_fast_from_str(a_values[i].key, &l_new_stake_lock_emission->tx_for_stake_lock_hash);
        l_new_stake_lock_emission->tx_used_out = *(dap_hash_fast_t *)(a_values[i].value);
        HASH_ADD(hh, l_ledger_pvt->emissions_for_stake_lock, tx_for_stake_lock_hash, sizeof(dap_chain_hash_fast_t), l_new_stake_lock_emission);
    }

    char* l_gdb_group = dap_ledger_get_gdb_group(l_ledger, DAP_LEDGER_TXS_STR);
    dap_global_db_get_all(l_gdb_group, 0, s_load_cache_gdb_loaded_txs_callback, l_ledger);
    DAP_DELETE(l_gdb_group);
    return true;
}

void dap_ledger_load_end(dap_ledger_t *a_ledger)
{
    pthread_rwlock_wrlock(&PVT(a_ledger)->ledger_rwlock);
    HASH_SORT(PVT(a_ledger)->ledger_items, s_sort_ledger_tx_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
}

static dap_ledger_reward_item_t *s_find_reward(dap_ledger_t *a_ledger, dap_ledger_reward_key_t *a_search_key)
{
    dap_ledger_reward_item_t *l_reward_item = NULL;
    pthread_rwlock_rdlock(&PVT(a_ledger)->rewards_rwlock);
    HASH_FIND(hh, PVT(a_ledger)->rewards, a_search_key, sizeof(*a_search_key), l_reward_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->rewards_rwlock);
    return l_reward_item;
}

bool dap_ledger_is_used_reward(dap_ledger_t *a_ledger, dap_hash_fast_t *a_block_hash, dap_hash_fast_t *a_sign_pkey_hash)
{
    dap_ledger_reward_key_t l_search_key = { .block_hash = *a_block_hash, .sign_pkey_hash = *a_sign_pkey_hash };
    return s_find_reward(a_ledger, &l_search_key);
}

/**
 * Checking a new transaction before adding to the cache
 *
 * return 0 OK, otherwise error
 */
// Checking a new transaction before adding to the cache
static int s_tx_cache_check(dap_ledger_t *a_ledger,
                            dap_chain_datum_tx_t *a_tx,
                            dap_hash_fast_t *a_tx_hash,
                            bool a_from_threshold,
                            dap_list_t **a_list_bound_items,
                            dap_list_t **a_list_tx_out,
                            char *a_main_ticker,
                            dap_chain_srv_uid_t *a_tag,
                            dap_chain_tx_tag_action_type_t *a_action,
                            bool a_check_for_removing)
{
    dap_return_val_if_fail(a_ledger && a_tx && a_tx_hash, DAP_LEDGER_CHECK_INVALID_ARGS);
    if (!a_from_threshold) {
        dap_ledger_tx_item_t *l_ledger_item = NULL;
        pthread_rwlock_rdlock(&PVT(a_ledger)->ledger_rwlock);
        HASH_FIND(hh, PVT(a_ledger)->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_ledger_item);
        pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
        if (l_ledger_item && !a_check_for_removing ) {     // transaction already present in the cache list
            if (g_debug_ledger) {
                log_it(L_WARNING, "Transaction %s already present in the cache", dap_chain_hash_fast_to_str_static(a_tx_hash));
                if (a_tag) *a_tag = l_ledger_item->cache_data.tag;
                if (a_action) *a_action = l_ledger_item->cache_data.action;
            }
            return DAP_LEDGER_CHECK_ALREADY_CACHED;
        } else if (!l_ledger_item && a_check_for_removing) {     // transaction already present in the cache list
            debug_if(g_debug_ledger, L_WARNING, "Transaction %s not present in the cache. Can not delete it. Skip.", dap_chain_hash_fast_to_str_static(a_tx_hash));
            return DAP_LEDGER_TX_CHECK_FOR_REMOVING_CANT_FIND_TX;
        }
    }
/*
 * Steps of checking for current transaction tx2 and every previous transaction tx1:
 * 1. valid(tx2.dap_chain_datum_tx_sig.pkey)
 * &&
 * 2. tx2.input != tx2.inputs.used
 * &&
 * 3. !is_used_out(tx1.dap_chain_datum_tx_out)
 * &&
 * 4. tx1.dap_chain_datum_tx_out.addr.data.key == tx2.dap_chain_datum_tx_sig.pkey for unconditional output
 * \\
 * 5. tx1.dap_chain_datum_tx_out.condition == verify_svc_type(tx2) for conditional output
 * &&
 * 6. sum(  find (tx2.input.tx_prev_hash).output[tx2.input_tx_prev_idx].value )  ==  sum (tx2.outputs.value) per token
 * &&
 * 7. valid(fee)
*/
    dap_list_t *l_list_bound_items = NULL;
    dap_list_t *l_list_tx_out = NULL;

    // sum of values in 'out' items from the previous transactions
    dap_ledger_tokenizer_t *l_values_from_prev_tx = NULL, *l_values_from_cur_tx = NULL,
                                 *l_value_cur = NULL, *l_tmp = NULL, *l_res = NULL;
    const char *l_token = NULL, *l_main_ticker = NULL;

    int l_err_num = DAP_LEDGER_CHECK_OK;
    int l_prev_tx_count = 0;

    // 1. Verify signature in current transaction
    if (!a_from_threshold && dap_chain_datum_tx_verify_sign(a_tx))
        return DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS;

    // ----------------------------------------------------------------
    // find all 'in' && 'in_cond' && 'in_ems' && 'in_reward'  items in current transaction
    dap_list_t *l_list_in = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_IN_ALL, &l_prev_tx_count);
    if (!l_list_in) {
        log_it(L_WARNING, "Tx check: no valid inputs found");
        return DAP_LEDGER_TX_CHECK_TX_NO_VALID_INPUTS;
    }
    dap_chain_hash_fast_t l_tx_first_sign_pkey_hash = {};
    dap_pkey_t *l_tx_first_sign_pkey = NULL;
    bool l_girdled_ems_used = false;
    uint256_t l_taxed_value = {};

    if(a_tag) dap_ledger_deduct_tx_tag(a_ledger, a_tx, NULL, a_tag, a_action);

    // find all previous transactions
    for (dap_list_t *it = l_list_in; it; it = it->next) {
         dap_ledger_tx_bound_t *l_bound_item = DAP_NEW_Z(dap_ledger_tx_bound_t);
        if (!l_bound_item) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            l_err_num = DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
            break;
        }
        l_list_bound_items = dap_list_append(l_list_bound_items, l_bound_item);

        uint8_t l_cond_type = *(uint8_t *)it->data;
        l_bound_item->type = l_cond_type;
        uint256_t l_value = uint256_0;
        void *l_tx_prev_out = NULL;
        dap_chain_datum_tx_t *l_tx_prev = NULL;
        dap_ledger_token_emission_item_t *l_emission_item = NULL;
        dap_ledger_stake_lock_item_t *l_stake_lock_emission = NULL;
        bool l_girdled_ems = false;

        switch (l_cond_type) {
        case TX_ITEM_TYPE_IN_EMS: {   // It's the emission (base) TX
            dap_chain_tx_in_ems_t *l_tx_in_ems = it->data;
            l_token = l_tx_in_ems->header.ticker;
            if (!dap_chain_datum_token_check_ticker(l_token)) {
                l_err_num = DAP_LEDGER_CHECK_INVALID_TICKER;
                break;
            }
            dap_hash_fast_t *l_emission_hash = &l_tx_in_ems->header.token_emission_hash;
            // 2. Check current transaction for doubles in input items list
            for (dap_list_t *l_iter = it->next; l_iter; l_iter = l_iter->next) {
                dap_chain_tx_in_ems_t *l_in_ems_check = l_iter->data;
                if (l_in_ems_check->header.type == TX_ITEM_TYPE_IN_EMS &&
                    dap_hash_fast_compare(&l_in_ems_check->header.token_emission_hash, l_emission_hash) && !a_check_for_removing)
                {
                    debug_if(g_debug_ledger, L_ERROR, "Emission output already used in current tx");
                    l_err_num = DAP_LEDGER_TX_CHECK_PREV_OUT_ALREADY_USED_IN_CURRENT_TX;
                    break;
                }
            }
            if (l_err_num)
                break;
            if ((l_girdled_ems = dap_hash_fast_is_blank(l_emission_hash)) ||
                    (l_stake_lock_emission = s_emissions_for_stake_lock_item_find(a_ledger, l_emission_hash))) {
                dap_chain_datum_tx_t *l_tx_stake_lock = a_tx;
                // 3. Check emission for STAKE_LOCK
                if (!dap_hash_fast_is_blank(l_emission_hash)) {
                    dap_hash_fast_t cur_tx_hash;
                    dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), &cur_tx_hash);
                    if (!dap_hash_fast_is_blank(&l_stake_lock_emission->tx_used_out) && !a_check_for_removing) {
                        if (!dap_hash_fast_compare(&cur_tx_hash, &l_stake_lock_emission->tx_used_out))
                            debug_if(g_debug_ledger, L_WARNING, "stake_lock_emission already present in cache for IN_EMS [%s]", l_token);
                        else
                            debug_if(g_debug_ledger, L_WARNING, "stake_lock_emission is used out for IN_EMS [%s]", l_token);
                        l_err_num = DAP_LEDGER_TX_CHECK_STAKE_LOCK_IN_EMS_ALREADY_USED;
                        break;
                    }
                    l_tx_stake_lock = dap_ledger_tx_find_by_hash(a_ledger, l_emission_hash);
                } else {
                    // 2. The only allowed item with girdled emission
                    if (l_girdled_ems_used && !a_check_for_removing) {
                        debug_if(g_debug_ledger, L_WARNING, "stake_lock_emission is used out for IN_EMS [%s]", l_token);
                        l_err_num = DAP_LEDGER_TX_CHECK_STAKE_LOCK_IN_EMS_ALREADY_USED;
                        break;
                    } else
                        l_girdled_ems_used = true;
                }
                if (!l_tx_stake_lock) {
                    debug_if(g_debug_ledger, L_WARNING, "Not found stake_lock transaction");
                    l_err_num = DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION;
                    break;
                }

                dap_ledger_token_item_t *l_delegated_item = dap_ledger_pvt_find_token(a_ledger, l_token);
                if (!l_delegated_item) {
                    debug_if(g_debug_ledger, L_WARNING, "Token [%s] not found", l_token);
                    l_err_num = DAP_LEDGER_CHECK_TICKER_NOT_FOUND;
                    break;
                }
                if (!l_delegated_item->is_delegated) {
                    debug_if(g_debug_ledger, L_WARNING, "Token [%s] not valid for stake_lock transaction", l_token);
                    l_err_num = DAP_LEDGER_TX_CHECK_STAKE_LOCK_INVALID_TOKEN;
                    break;
                }
                if (!dap_ledger_token_ticker_check(a_ledger, l_delegated_item->delegated_from)) {
                    debug_if(g_debug_ledger, L_WARNING, "Token [%s] not found", l_delegated_item->delegated_from);
                    l_err_num = DAP_LEDGER_CHECK_TICKER_NOT_FOUND;
                    break;
                }

                if (l_girdled_ems)
                    l_main_ticker = l_delegated_item->delegated_from;

                dap_chain_tx_out_cond_t *l_tx_stake_lock_out_cond = dap_chain_datum_tx_out_cond_get(l_tx_stake_lock, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK, NULL);
                if (!l_tx_stake_lock_out_cond) {
                    debug_if(g_debug_ledger, L_WARNING, "No OUT_COND of stake_lock subtype for IN_EMS [%s]", l_tx_in_ems->header.ticker);
                    l_err_num = DAP_LEDGER_TX_CHECK_STAKE_LOCK_NO_OUT_COND_FOR_IN_EMS;
                    break;
                }
                uint256_t l_value_expected ={};
                if (MULT_256_COIN(l_tx_stake_lock_out_cond->header.value, l_delegated_item->emission_rate, &l_value_expected)) {
                    if (g_debug_ledger) {
                        char *l_emission_rate_str = dap_chain_balance_coins_print(l_delegated_item->emission_rate);
                        const char *l_locked_value_str; dap_uint256_to_char(l_tx_stake_lock_out_cond->header.value, &l_locked_value_str);
                        log_it( L_WARNING, "Multiplication overflow for %s emission: locked value %s emission rate %s",
                                                                l_tx_in_ems->header.ticker, l_locked_value_str, l_emission_rate_str);
                        DAP_DEL_Z(l_emission_rate_str);
                    }
                    l_err_num = DAP_LEDGER_CHECK_INTEGER_OVERFLOW;
                    break;
                }
                dap_chain_tx_out_ext_t *l_tx_out_ext = NULL;
                uint256_t l_stake_lock_ems_value = {};
                int l_item_idx = 0;
                do {
                    l_tx_out_ext = (dap_chain_tx_out_ext_t *)dap_chain_datum_tx_item_get(a_tx, &l_item_idx, NULL, TX_ITEM_TYPE_OUT_EXT, NULL);
                    if (!l_tx_out_ext) {
                        if (l_girdled_ems) {
                            debug_if(g_debug_ledger, L_WARNING, "No OUT_EXT for girdled IN_EMS [%s]", l_tx_in_ems->header.ticker);
                            l_err_num = DAP_LEDGER_TX_CHECK_NO_OUT_EXT_FOR_GIRDLED_IN_EMS;
                        }
                        break;
                    }
                    l_item_idx++;
                } while (strcmp(l_tx_out_ext->token, l_token));
                if (!l_tx_out_ext) {
                    dap_chain_tx_out_t *l_tx_out = (dap_chain_tx_out_t *)dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_OUT, NULL);
                    if (!l_tx_out) {
                        debug_if(true, L_WARNING, "Can't find OUT nor OUT_EXT item for base TX with IN_EMS [%s]", l_tx_in_ems->header.ticker);
                        l_err_num = DAP_LEDGER_TX_CHECK_NO_OUT_ITEMS_FOR_BASE_TX;
                        break;
                    } else
                        l_stake_lock_ems_value = l_tx_out->header.value;
                } else
                    l_stake_lock_ems_value = l_tx_out_ext->header.value;
                if (!dap_ledger_pvt_token_supply_check(l_delegated_item, l_stake_lock_ems_value)) {
                    l_err_num = DAP_LEDGER_EMISSION_CHECK_VALUE_EXCEEDS_CURRENT_SUPPLY;
                    break;
                }
                if (!EQUAL_256(l_value_expected, l_stake_lock_ems_value)) {
                    // !!! A terrible legacy crutch, TODO !!!
                    SUM_256_256(l_value_expected, GET_256_FROM_64(10), &l_value_expected);
                    if (!EQUAL_256(l_value_expected, l_stake_lock_ems_value)) {
                            char *l_value_expected_str = dap_chain_balance_datoshi_print(l_value_expected);
                            char *l_locked_value_str = dap_chain_balance_datoshi_print(l_stake_lock_ems_value);

                            debug_if(g_debug_ledger, L_WARNING, "Value %s != %s expected for [%s]",l_locked_value_str, l_value_expected_str,
                                     l_tx_in_ems->header.ticker);

                            DAP_DEL_Z(l_value_expected_str);
                            DAP_DEL_Z(l_locked_value_str);
                            l_err_num = DAP_LEDGER_TX_CHECK_STAKE_LOCK_UNEXPECTED_VALUE;
                            break;
                    }
                }
                if (!l_girdled_ems) {
                    // check tiker
                    const char *l_tx_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, l_emission_hash);
                    if (!l_tx_ticker) {
                        debug_if(g_debug_ledger, L_WARNING, "No ticker found for stake_lock tx [expected '%s']", l_tx_in_ems->header.ticker);
                        l_err_num = DAP_LEDGER_CHECK_TICKER_NOT_FOUND;
                        break;
                    }
                    if (strcmp(l_tx_ticker, l_delegated_item->delegated_from)) {
                        debug_if(g_debug_ledger, L_WARNING, "Ticker '%s' != expected '%s'", l_tx_ticker, l_tx_in_ems->header.ticker);
                        l_err_num = DAP_LEDGER_TX_CHECK_STAKE_LOCK_OTHER_TICKER_EXPECTED;
                        break;
                    }
                }
                debug_if(g_debug_ledger, L_NOTICE, "Check emission passed for IN_EMS [%s]", l_tx_in_ems->header.ticker);
                if (l_stake_lock_emission) {
                    l_bound_item->stake_lock_item = l_stake_lock_emission;
                    l_value = l_stake_lock_ems_value;
                } else // girdled emission
                    l_value = l_tx_out_ext->header.value;
                l_bound_item->token_item = l_delegated_item;
                l_bound_item->type = TX_ITEM_TYPE_IN_EMS_LOCK;
            } else if ( (l_emission_item = dap_ledger_pvt_emission_item_find(a_ledger, l_token, l_emission_hash, &l_bound_item->token_item)) ) {
                // 3. Check AUTH token emission
                if (!dap_hash_fast_is_blank(&l_emission_item->tx_used_out)  && !a_check_for_removing) {
                    debug_if(g_debug_ledger, L_WARNING, "Emission for IN_EMS [%s] is already used", l_tx_in_ems->header.ticker);
                    l_err_num = DAP_LEDGER_TX_CHECK_IN_EMS_ALREADY_USED;
                    break;
                }
                l_value = l_emission_item->datum_token_emission->hdr.value;
                l_bound_item->emission_item = l_emission_item;
            } else {
                l_err_num = DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION;
                break;
            }
        } break;

        case TX_ITEM_TYPE_IN_REWARD: {
            dap_chain_tx_in_reward_t *l_tx_in_reward = it->data;
            dap_hash_fast_t *l_block_hash = &l_tx_in_reward->block_hash;
            // 2. Check current transaction for doubles in input items list
            for (dap_list_t *l_iter = l_list_in; l_iter; l_iter = l_iter->next) {
                dap_chain_tx_in_reward_t *l_in_reward_check = l_iter->data;
                if (l_tx_in_reward != l_in_reward_check &&
                        l_in_reward_check->type == TX_ITEM_TYPE_IN_REWARD &&
                        dap_hash_fast_compare(&l_in_reward_check->block_hash, l_block_hash) && !a_check_for_removing) {
                    debug_if(g_debug_ledger, L_ERROR, "Reward for this block sign already used in current tx");
                    l_err_num = DAP_LEDGER_TX_CHECK_PREV_OUT_ALREADY_USED_IN_CURRENT_TX;
                    break;
                }
            }
            if (l_err_num)
                break;
            if (!l_tx_first_sign_pkey) {
                // Get sign item
                dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t*) dap_chain_datum_tx_item_get(a_tx, NULL, NULL,
                        TX_ITEM_TYPE_SIG, NULL);
                assert(l_tx_sig);
                // Get sign from sign item
                dap_sign_t *l_tx_first_sign = dap_chain_datum_tx_item_sign_get_sig(l_tx_sig);
                assert(l_tx_first_sign);
                // calculate hash from sign public key
                dap_sign_get_pkey_hash(l_tx_first_sign, &l_tx_first_sign_pkey_hash);
                l_tx_first_sign_pkey = dap_pkey_get_from_sign(l_tx_first_sign);
            }
            // 3. Check if already spent reward
            dap_ledger_reward_key_t l_search_key = { .block_hash = *l_block_hash, .sign_pkey_hash = l_tx_first_sign_pkey_hash };
            dap_ledger_reward_item_t *l_reward_item = s_find_reward(a_ledger, &l_search_key);
            if (l_reward_item && !a_check_for_removing) {
                l_err_num = DAP_LEDGER_TX_CHECK_REWARD_ITEM_ALREADY_USED;
                char l_block_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE],
                     l_sign_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE],
                     l_spender_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_chain_hash_fast_to_str(l_block_hash, l_block_hash_str, sizeof(l_block_hash_str));
                dap_chain_hash_fast_to_str(&l_tx_first_sign_pkey_hash, l_sign_hash_str, sizeof(l_sign_hash_str));
                dap_chain_hash_fast_to_str(&l_reward_item->spender_tx, l_spender_hash_str, sizeof(l_spender_hash_str));
                debug_if(g_debug_ledger, L_WARNING, "Reward for block %s sign %s already spent by %s", l_block_hash_str, l_sign_hash_str, l_spender_hash_str);
                break;
            }
            // Check reward legitimacy & amount
            dap_chain_t *l_chain;
            DL_FOREACH(a_ledger->net->pub.chains, l_chain) {
                if (l_chain->callback_calc_reward) {
                    l_value = l_chain->callback_calc_reward(l_chain, l_block_hash, l_tx_first_sign_pkey);
                    break;
                }
            }
            if (IS_ZERO_256(l_value)) {
                l_err_num = DAP_LEDGER_TX_CHECK_REWARD_ITEM_ILLEGAL;
                char l_block_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE],
                     l_sign_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_chain_hash_fast_to_str(l_block_hash, l_block_hash_str, sizeof(l_block_hash_str));
                dap_chain_hash_fast_to_str(&l_tx_first_sign_pkey_hash, l_sign_hash_str, sizeof(l_sign_hash_str));
                debug_if(g_debug_ledger, L_DEBUG, "Can't find block %s with sign %s", l_block_hash_str, l_sign_hash_str);
                break;
            }
            // Reward nominated in net native ticker only
            l_token = l_main_ticker = a_ledger->net->pub.native_ticker;
            dap_ledger_token_item_t *l_token_item = dap_ledger_pvt_find_token(a_ledger, l_token);
            if (!l_token_item) {
                debug_if(g_debug_ledger, L_ERROR, "Native token ticker not found");
                l_err_num = DAP_LEDGER_CHECK_TICKER_NOT_FOUND;
                break;
            }
            if (!dap_ledger_pvt_token_supply_check(l_token_item, l_value) && !a_check_for_removing) {
                l_err_num = DAP_LEDGER_EMISSION_CHECK_VALUE_EXCEEDS_CURRENT_SUPPLY;
                break;
            }
            l_bound_item->token_item = l_token_item;
            l_bound_item->reward_key = l_search_key;
            // Overflow checked later with overall values sum
            SUM_256_256(l_taxed_value, l_value, &l_taxed_value);
        } break;

        case TX_ITEM_TYPE_IN:
        case TX_ITEM_TYPE_IN_COND: { // Not emission types
            uint32_t l_tx_prev_out_idx = (uint32_t)-1;
            dap_hash_fast_t *l_tx_prev_hash;
            if (l_cond_type == TX_ITEM_TYPE_IN) {
                dap_chain_tx_in_t *l_tx_in = it->data;
                l_tx_prev_hash = &l_tx_in->header.tx_prev_hash;
                if (dap_hash_fast_is_blank(l_tx_prev_hash)) {
                    DAP_DELETE(l_bound_item);
                    l_list_bound_items = dap_list_delete_link(l_list_bound_items, dap_list_last(l_list_bound_items));
                    continue; // old base tx compliance
                }
                l_tx_prev_out_idx = l_tx_in->header.tx_out_prev_idx;
                // 2. Check current transaction for doubles in input items list
                for (dap_list_t *l_iter = l_list_in; l_iter; l_iter = l_iter->next) {
                    dap_chain_tx_in_t *l_in_check = l_iter->data;
                    if (l_tx_in != l_in_check &&
                            l_in_check->header.type == TX_ITEM_TYPE_IN &&
                            l_in_check->header.tx_out_prev_idx == l_tx_prev_out_idx &&
                            dap_hash_fast_compare(&l_in_check->header.tx_prev_hash, l_tx_prev_hash) && !a_check_for_removing) {
                        debug_if(g_debug_ledger, L_ERROR, "This previous tx output already used in current tx");
                        l_err_num = DAP_LEDGER_TX_CHECK_PREV_OUT_ALREADY_USED_IN_CURRENT_TX;
                        break;
                    }
                }
                if (l_err_num)
                    break;
            } else {
                dap_chain_tx_in_cond_t *l_tx_in_cond = it->data;
                l_tx_prev_hash = &l_tx_in_cond->header.tx_prev_hash;
                l_tx_prev_out_idx = l_tx_in_cond->header.tx_out_prev_idx;
                // 2. Check current transaction for doubles in input items list
                for (dap_list_t *l_iter = l_list_in; l_iter; l_iter = l_iter->next) {
                    dap_chain_tx_in_cond_t *l_in_cond_check = l_iter->data;
                    if (l_tx_in_cond != l_in_cond_check &&
                            l_in_cond_check->header.type == TX_ITEM_TYPE_IN_COND &&
                            l_in_cond_check->header.tx_out_prev_idx == l_tx_prev_out_idx &&
                            dap_hash_fast_compare(&l_in_cond_check->header.tx_prev_hash, l_tx_prev_hash) && !a_check_for_removing) {
                        debug_if(g_debug_ledger, L_ERROR, "This previous tx output already used in current tx");
                        l_err_num = DAP_LEDGER_TX_CHECK_PREV_OUT_ALREADY_USED_IN_CURRENT_TX;
                        break;
                    }
                }
                if (l_err_num)
                    break;
            }
            // Get previous transaction in the cache by hash
            dap_ledger_tx_item_t *l_item_out = NULL;
            l_tx_prev = s_tx_find_by_hash(a_ledger, l_tx_prev_hash, &l_item_out, false);
            char l_tx_prev_hash_str[DAP_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(l_tx_prev_hash, l_tx_prev_hash_str, DAP_HASH_FAST_STR_SIZE);
            if (!l_tx_prev) { // Unchained transaction or previous TX was already spent and removed from ledger
                debug_if(g_debug_ledger && !a_from_threshold, L_DEBUG, "No previous transaction was found for hash %s", l_tx_prev_hash_str);
                l_err_num = DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS;
                break;
            } else if (l_item_out->cache_data.ts_spent && !a_check_for_removing) {
                l_err_num = DAP_LEDGER_TX_CHECK_OUT_ITEM_ALREADY_USED;
                debug_if(g_debug_ledger, L_WARNING, "All 'out' items of previous tx %s were already spent", l_tx_prev_hash_str);
                break;
            }
            l_bound_item->prev_item = l_item_out;
            l_bound_item->prev_out_idx = l_tx_prev_out_idx;
            l_token = l_item_out->cache_data.token_ticker;
            debug_if(g_debug_ledger && !a_from_threshold, L_INFO, "Previous transaction was found for hash %s",l_tx_prev_hash_str);

            // 2. Check if out in previous transaction has spent
            dap_hash_fast_t l_spender = {};
            if (s_ledger_tx_hash_is_used_out_item(l_item_out, l_tx_prev_out_idx, &l_spender) && !a_check_for_removing) {
                l_err_num = DAP_LEDGER_TX_CHECK_OUT_ITEM_ALREADY_USED;
                char l_hash[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_chain_hash_fast_to_str(&l_spender, l_hash, sizeof(l_hash));
                debug_if(g_debug_ledger, L_INFO, "'Out' item of previous tx %s already spent by %s", l_tx_prev_hash_str, l_hash);
                break;
            }

            // Get one 'out' item in previous transaction bound with current 'in' item
            l_tx_prev_out = dap_chain_datum_tx_item_get_nth(l_tx_prev, TX_ITEM_TYPE_OUT_ALL, l_tx_prev_out_idx);
            if(!l_tx_prev_out) {
                l_err_num = DAP_LEDGER_TX_CHECK_PREV_OUT_ITEM_NOT_FOUND;
                break;
            }
            if (dap_hash_fast_is_blank(&l_tx_first_sign_pkey_hash)) {
                // Get sign item
                dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t*) dap_chain_datum_tx_item_get(a_tx, NULL, NULL,
                        TX_ITEM_TYPE_SIG, NULL);
                assert(l_tx_sig);
                // Get sign from sign item
                dap_sign_t *l_tx_first_sign = dap_chain_datum_tx_item_sign_get_sig(l_tx_sig);
                assert(l_tx_first_sign);
                // calculate hash from sign public key
                dap_sign_get_pkey_hash(l_tx_first_sign, &l_tx_first_sign_pkey_hash);
            }
            if (l_cond_type == TX_ITEM_TYPE_IN) {
                dap_chain_addr_t *l_addr_from = NULL;
                dap_chain_tx_item_type_t l_type = *(uint8_t *)l_tx_prev_out;
                switch (l_type) {
                case TX_ITEM_TYPE_OUT_OLD: // Deprecated
                    l_addr_from = &((dap_chain_tx_out_old_t *)l_tx_prev_out)->addr;
                    l_value = dap_chain_uint256_from(((dap_chain_tx_out_old_t *)l_tx_prev_out)->header.value);
                    break;
                case TX_ITEM_TYPE_OUT:
                    l_addr_from = &((dap_chain_tx_out_t *)l_tx_prev_out)->addr;
                    l_value = ((dap_chain_tx_out_t *)l_tx_prev_out)->header.value;
                    break;
                case TX_ITEM_TYPE_OUT_EXT:
                    l_addr_from = &((dap_chain_tx_out_ext_t *)l_tx_prev_out)->addr;
                    l_value = ((dap_chain_tx_out_ext_t *)l_tx_prev_out)->header.value;
                    l_token = ((dap_chain_tx_out_ext_t *)l_tx_prev_out)->token;
                    break;
                default:
                    l_err_num = DAP_LEDGER_TX_CHECK_PREV_OUT_ITEM_MISSTYPED;
                    break;
                }
                if (l_err_num)
                    break;
                l_bound_item->in.addr_from = *l_addr_from;
                dap_strncpy(l_bound_item->in.token_ticker, l_token, DAP_CHAIN_TICKER_SIZE_MAX);
                // 4. compare public key hashes in the signature of the current transaction and in the 'out' item of the previous transaction
                if (l_addr_from->net_id.uint64 != a_ledger->net->pub.id.uint64 ||
                        !dap_hash_fast_compare(&l_tx_first_sign_pkey_hash, &l_addr_from->data.hash_fast)) {
                    l_err_num = DAP_LEDGER_TX_CHECK_PKEY_HASHES_DONT_MATCH;
                    break;
                }

                if ( !l_token || !*l_token ) {
                    log_it(L_WARNING, "No token ticker found in previous transaction");
                    l_err_num = DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER;
                    break;
                }
                // Get permissions
                dap_ledger_token_item_t *l_token_item = dap_ledger_pvt_find_token(a_ledger, l_token);
                if (!l_token_item) {
                    debug_if(g_debug_ledger, L_WARNING, "Token with ticker %s not found", l_token);
                    l_err_num = DAP_LEDGER_CHECK_TICKER_NOT_FOUND;
                    break;
                }
                // Check permissions
                if (dap_ledger_pvt_addr_check(l_token_item, l_addr_from, false) == DAP_LEDGER_CHECK_ADDR_FORBIDDEN) {
                    debug_if(g_debug_ledger, L_WARNING, "No permission to send for addr %s", dap_chain_addr_to_str_static(l_addr_from));
                    l_err_num = DAP_LEDGER_CHECK_ADDR_FORBIDDEN;
                    break;
                }
            } else { // l_cond_type == TX_ITEM_TYPE_IN_COND
                if(*(uint8_t *)l_tx_prev_out != TX_ITEM_TYPE_OUT_COND) {
                    l_err_num = DAP_LEDGER_TX_CHECK_PREV_OUT_ITEM_MISSTYPED;
                    break;
                }
                dap_chain_tx_out_cond_t *l_tx_prev_out_cond = NULL;
                l_tx_prev_out_cond = (dap_chain_tx_out_cond_t *)l_tx_prev_out;

                // 5a. Check for condition owner
                // Get owner tx
                dap_hash_fast_t l_owner_tx_hash = dap_ledger_get_first_chain_tx_hash(a_ledger, l_tx_prev_out_cond->header.subtype, l_tx_prev_hash);
                dap_chain_datum_tx_t *l_owner_tx = dap_hash_fast_is_blank(&l_owner_tx_hash)
                    ? l_tx_prev
                    : dap_ledger_tx_find_by_hash(a_ledger, &l_owner_tx_hash);
                dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
                dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_sig);
                dap_chain_tx_sig_t *l_owner_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(l_owner_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
                dap_sign_t *l_owner_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_owner_tx_sig);

                bool l_owner = false;
                l_owner = dap_sign_compare_pkeys(l_owner_sign, l_sign);

                // 5b. Call verificator for conditional output
                dap_ledger_verificator_t *l_verificator = NULL;
                int l_sub_tmp = l_tx_prev_out_cond->header.subtype;

                pthread_rwlock_rdlock(&s_verificators_rwlock);
                HASH_FIND_INT(s_verificators, &l_sub_tmp, l_verificator);
                pthread_rwlock_unlock(&s_verificators_rwlock);
                if (!l_verificator || !l_verificator->callback) {
                    debug_if(g_debug_ledger, L_ERROR, "No verificator set for conditional output subtype %d", l_sub_tmp);
                    l_err_num = DAP_LEDGER_TX_CHECK_NO_VERIFICATOR_SET;
                    break;
                }

                int l_verificator_error = l_verificator->callback(a_ledger, l_tx_prev_out_cond, a_tx, l_owner);
                if (l_verificator_error != DAP_LEDGER_CHECK_OK) { // TODO add string representation for verificator return codes
                    debug_if(g_debug_ledger, L_WARNING, "Verificator check error %d for conditional output %s",
                                                                    l_verificator_error, dap_chain_tx_out_cond_subtype_to_str(l_sub_tmp));
                    l_err_num = DAP_LEDGER_TX_CHECK_VERIFICATOR_CHECK_FAILURE;
                    break;
                }
                l_bound_item->cond = l_tx_prev_out_cond;
                l_value = l_tx_prev_out_cond->header.value;
                if (l_tx_prev_out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE) {
                    l_token = a_ledger->net->pub.native_ticker;
                    // Overflow checked later with overall values sum
                    SUM_256_256(l_taxed_value, l_value, &l_taxed_value);
                }
                l_main_ticker = l_token;
            }
        } break;

        default:
            break;
        }
        if (l_err_num)
            break;

        l_bound_item->value = l_value;

        if (l_cond_type != TX_ITEM_TYPE_IN) {
            // If not checked earlier
            if (!l_token || !*l_token) {
                log_it(L_WARNING, "No token ticker found in previous transaction");
                l_err_num = DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER;
                break;
            }
        }
        HASH_FIND_STR(l_values_from_prev_tx, l_token, l_value_cur);
        if (!l_value_cur) {
            l_value_cur = DAP_NEW_Z(dap_ledger_tokenizer_t);
            if ( !l_value_cur ) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                l_err_num = DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
                break;
            }
            strcpy(l_value_cur->token_ticker, l_token);
            HASH_ADD_STR(l_values_from_prev_tx, token_ticker, l_value_cur);
        }
        // calculate  from previous transactions per each token
        if (SUM_256_256(l_value_cur->sum, l_value, &l_value_cur->sum)) {
            debug_if(g_debug_ledger, L_WARNING, "Sum result overflow for tx_add_check with ticker %s",
                                    l_value_cur->token_ticker);
            l_err_num = DAP_LEDGER_CHECK_INTEGER_OVERFLOW;
            break;
        }
    }

    dap_list_free(l_list_in);
    DAP_DELETE(l_tx_first_sign_pkey);
    if (l_err_num) {
        if ( l_list_bound_items )
            dap_list_free_full(l_list_bound_items, NULL);
        HASH_ITER(hh, l_values_from_prev_tx, l_value_cur, l_tmp) {
            HASH_DEL(l_values_from_prev_tx, l_value_cur);
            DAP_DELETE(l_value_cur);
        }
        return l_err_num;
    }

    // 6. Compare sum of values in 'out' items in the current transaction and in the previous transactions
    // Calculate the sum of values in 'out' items from the current transaction
    bool l_multichannel = false;
    if (HASH_COUNT(l_values_from_prev_tx) > 1) {
        l_multichannel = true;
        if (HASH_COUNT(l_values_from_prev_tx) == 2 && !l_main_ticker) {
            HASH_FIND_STR(l_values_from_prev_tx, a_ledger->net->pub.native_ticker, l_value_cur);
            if (l_value_cur) {
                l_value_cur = l_value_cur->hh.next ? l_value_cur->hh.next : l_value_cur->hh.prev;
                l_main_ticker = l_value_cur->token_ticker;
            }
        }
    } else {
        l_value_cur = DAP_NEW_Z(dap_ledger_tokenizer_t);
        if ( !l_value_cur ) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            l_err_num = DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
            if ( l_list_bound_items )
                dap_list_free_full(l_list_bound_items, NULL);
            HASH_ITER(hh, l_values_from_prev_tx, l_value_cur, l_tmp) {
                HASH_DEL(l_values_from_prev_tx, l_value_cur);
                DAP_DELETE(l_value_cur);
            }
            return l_err_num;
        }
        dap_stpcpy(l_value_cur->token_ticker, l_token);
        if (!l_main_ticker)
            l_main_ticker = l_value_cur->token_ticker;
        HASH_ADD_STR(l_values_from_cur_tx, token_ticker, l_value_cur);
    }
    dap_chain_addr_t l_sovereign_addr;
    uint256_t l_sovereign_tax;
    bool l_tax_check = s_tax_callback ? s_tax_callback(a_ledger->net->pub.id, &l_tx_first_sign_pkey_hash, &l_sovereign_addr, &l_sovereign_tax)
                                      : false;
    // find 'out' items
    uint256_t l_value = {}, l_fee_sum = {}, l_tax_sum = {};
    bool l_fee_check = !IS_ZERO_256(a_ledger->net->pub.fee_value) && !dap_chain_addr_is_blank(&a_ledger->net->pub.fee_addr);
    int l_item_idx = 0;
    byte_t *it; size_t l_size;
    TX_ITEM_ITER_TX(it, l_size, a_tx) {
        dap_chain_addr_t l_tx_out_to = { };
        switch ( *it ) {
        case TX_ITEM_TYPE_OUT_OLD: {
            dap_chain_tx_out_old_t *l_tx_out = (dap_chain_tx_out_old_t*)it;
            if (l_multichannel) { // token ticker is mandatory for multichannel transactions
                l_err_num = DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER;
                break;
            }
            l_value = dap_chain_uint256_from(l_tx_out->header.value);
            l_tx_out_to = l_tx_out->addr;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        case TX_ITEM_TYPE_OUT: { // 256
            dap_chain_tx_out_t *l_tx_out = (dap_chain_tx_out_t *)it;
            if (l_multichannel) { // token ticker is mandatory for multichannel transactions
                if (l_main_ticker)
                    l_token = l_main_ticker;
                else {
                    l_err_num = DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER;
                    break;
                }
            }
            l_value = l_tx_out->header.value;
            l_tx_out_to = l_tx_out->addr;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        case TX_ITEM_TYPE_OUT_EXT: { // 256
            dap_chain_tx_out_ext_t *l_tx_out = (dap_chain_tx_out_ext_t *)it;
            if (!l_multichannel) { // token ticker is forbiden for single-channel transactions
                l_err_num = DAP_LEDGER_TX_CHECK_UNEXPECTED_TOKENIZED_OUT;
                break;
            }
            l_value = l_tx_out->header.value;
            l_token = l_tx_out->token;
            l_tx_out_to = l_tx_out->addr;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        case TX_ITEM_TYPE_OUT_COND: {
            dap_chain_tx_out_cond_t *l_tx_out = (dap_chain_tx_out_cond_t *)it;
            if (l_multichannel) {
                if (l_tx_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)
                    l_token = (char *)a_ledger->net->pub.native_ticker;
                else if (l_main_ticker)
                    l_token = l_main_ticker;
                else {
                    log_it(L_WARNING, "No conditional output support for multichannel transaction");
                    l_err_num = DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER;
                    break;
                }
            }
            l_value = l_tx_out->header.value;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
            if (l_tax_check && l_tx_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE &&
                    SUBTRACT_256_256(l_taxed_value, l_value, &l_taxed_value)) {
                log_it(L_WARNING, "Fee is greater than sum of inputs");
                l_err_num = DAP_LEDGER_CHECK_INTEGER_OVERFLOW;
                break;
            }
        } break;
        default:
            continue;
        }

        if (l_err_num)
            break;
        if (l_multichannel) {
            HASH_FIND_STR(l_values_from_cur_tx, l_token, l_value_cur);
            if (!l_value_cur) {
                l_value_cur = DAP_NEW_Z(dap_ledger_tokenizer_t);
                if ( !l_value_cur ) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    l_err_num = DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
                    break;
                }
                strcpy(l_value_cur->token_ticker, l_token);
                HASH_ADD_STR(l_values_from_cur_tx, token_ticker, l_value_cur);
            }
        }
        if (SUM_256_256(l_value_cur->sum, l_value, &l_value_cur->sum)) {
            debug_if(g_debug_ledger, L_WARNING, "Sum result overflow for tx_add_check with ticker %s",
                                    l_value_cur->token_ticker);
            l_err_num = DAP_LEDGER_CHECK_INTEGER_OVERFLOW;
            break;
        }

        // Find token item
        dap_ledger_token_item_t *l_token_item = dap_ledger_pvt_find_token(a_ledger, l_token);
        if (!l_token_item) {
            debug_if(g_debug_ledger, L_WARNING, "Token with ticker %s not found", l_token);
            l_err_num = DAP_LEDGER_CHECK_TICKER_NOT_FOUND;
            break;
        }
        // Check permissions
        if (dap_ledger_pvt_addr_check(l_token_item, &l_tx_out_to, true) == DAP_LEDGER_CHECK_ADDR_FORBIDDEN) {
            debug_if(g_debug_ledger, L_WARNING, "No permission to receive for addr %s", dap_chain_addr_to_str_static(&l_tx_out_to));
            l_err_num = DAP_LEDGER_CHECK_ADDR_FORBIDDEN;
            break;
        }
        if (l_fee_check && dap_chain_addr_compare(&l_tx_out_to, &a_ledger->net->pub.fee_addr) &&
                !dap_strcmp(l_value_cur->token_ticker, a_ledger->net->pub.native_ticker))
            SUM_256_256(l_fee_sum, l_value, &l_fee_sum);

        if (l_tax_check && dap_chain_addr_compare(&l_tx_out_to, &l_sovereign_addr) &&
                !dap_strcmp(l_value_cur->token_ticker, a_ledger->net->pub.native_ticker))
            SUM_256_256(l_tax_sum, l_value, &l_tax_sum);
    }

    // Check for transaction consistency (sum(ins) == sum(outs))
    if (!l_err_num) {
        HASH_ITER(hh, l_values_from_prev_tx, l_value_cur, l_tmp) {
            HASH_FIND_STR(l_values_from_cur_tx, l_value_cur->token_ticker, l_res);
            if (!l_res || !EQUAL_256(l_res->sum, l_value_cur->sum) ) {
                if (g_debug_ledger) {
                    char *l_balance = dap_chain_balance_coins_print(l_res ? l_res->sum : uint256_0);
                    char *l_balance_cur = dap_chain_balance_coins_print(l_value_cur->sum);
                    log_it(L_ERROR, "Sum of values of out items from current tx (%s) is not equal outs from previous txs (%s) for token %s",
                            l_balance, l_balance_cur, l_value_cur->token_ticker);
                    DAP_DELETE(l_balance);
                    DAP_DELETE(l_balance_cur);
                }
                l_err_num = DAP_LEDGER_TX_CHECK_SUM_INS_NOT_EQUAL_SUM_OUTS;
                break;
            }
        }
    }

    // 7. Check the network fee
    if (!l_err_num && l_fee_check) {
        // Check for PoA-cert-signed "service" no-tax tx
        if (compare256(l_fee_sum, a_ledger->net->pub.fee_value) == -1 &&
                !dap_ledger_tx_poa_signed(a_ledger, a_tx)) {
            char *l_current_fee = dap_chain_balance_coins_print(l_fee_sum);
            char *l_expected_fee = dap_chain_balance_coins_print(a_ledger->net->pub.fee_value);
            log_it(L_WARNING, "Fee value is invalid, expected %s pointed %s", l_expected_fee, l_current_fee);
            l_err_num = DAP_LEDGER_TX_CHECK_NOT_ENOUGH_FEE;
            DAP_DEL_Z(l_current_fee);
            DAP_DEL_Z(l_expected_fee);
        }
        if (l_tax_check && SUBTRACT_256_256(l_taxed_value, l_fee_sum, &l_taxed_value)) {
            log_it(L_WARNING, "Fee is greater than sum of inputs");
            l_err_num = DAP_LEDGER_CHECK_INTEGER_OVERFLOW;
        }
    }

    // 8. Check sovereign tax
    if (l_tax_check && !l_err_num) {
        uint256_t l_expected_tax = {};
        MULT_256_COIN(l_taxed_value, l_sovereign_tax, &l_expected_tax);
        if (compare256(l_tax_sum, l_expected_tax) == -1) {
            char *l_current_tax_str = dap_chain_balance_coins_print(l_tax_sum);
            char *l_expected_tax_str = dap_chain_balance_coins_print(l_expected_tax);
            log_it(L_WARNING, "Tax value is invalid, expected %s pointed %s", l_expected_tax_str, l_current_tax_str);
            l_err_num = DAP_LEDGER_TX_CHECK_NOT_ENOUGH_TAX;
            DAP_DEL_Z(l_current_tax_str);
            DAP_DEL_Z(l_expected_tax_str);
        }
    }

    if (!l_err_num) {
        // TODO move it to service tag deduction
        if ( dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_VOTING, NULL ) ) {
            if (s_voting_callbacks.voting_callback) {
                if ((l_err_num = s_voting_callbacks.voting_callback(a_ledger, TX_ITEM_TYPE_VOTING, a_tx, a_tx_hash, false))) {
                    debug_if(g_debug_ledger, L_WARNING, "Verificator check error %d for voting", l_err_num);
                    l_err_num = DAP_LEDGER_TX_CHECK_VERIFICATOR_CHECK_FAILURE;
                }
            } else {
                debug_if(g_debug_ledger, L_WARNING, "Verificator check error for voting item");
                l_err_num = DAP_LEDGER_TX_CHECK_NO_VERIFICATOR_SET;
            }
            if (a_tag)
                a_tag->uint64 = DAP_CHAIN_TX_TAG_ACTION_VOTING;
        } else if ( dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_VOTE, NULL) ) {
           if (s_voting_callbacks.voting_callback) {
               if ((l_err_num = s_voting_callbacks.voting_callback(a_ledger, TX_ITEM_TYPE_VOTE, a_tx, a_tx_hash, false))) {
                   debug_if(g_debug_ledger, L_WARNING, "Verificator check error %d for vote", l_err_num);
                   l_err_num = DAP_LEDGER_TX_CHECK_VERIFICATOR_CHECK_FAILURE;
               }
           } else {
               debug_if(g_debug_ledger, L_WARNING, "Verificator check error for vote item");
               l_err_num = DAP_LEDGER_TX_CHECK_NO_VERIFICATOR_SET;
           }
           if (a_tag)
               a_tag->uint64 = DAP_CHAIN_TX_TAG_ACTION_VOTE;
        }
    }

    if (a_main_ticker && !l_err_num)
        dap_strncpy(a_main_ticker, l_main_ticker, DAP_CHAIN_TICKER_SIZE_MAX);

    HASH_ITER(hh, l_values_from_prev_tx, l_value_cur, l_tmp) {
        HASH_DEL(l_values_from_prev_tx, l_value_cur);
        DAP_DELETE(l_value_cur);
    }
    HASH_ITER(hh, l_values_from_cur_tx, l_value_cur, l_tmp) {
        HASH_DEL(l_values_from_cur_tx, l_value_cur);
        DAP_DELETE(l_value_cur);
    }
    if (!a_list_bound_items || l_err_num) {
        dap_list_free_full(l_list_bound_items, NULL);
    } else {
        *a_list_bound_items = l_list_bound_items;
    }

    if (!a_list_tx_out || l_err_num) {
        dap_list_free(l_list_tx_out);
    } else {
        *a_list_tx_out = l_list_tx_out;
    }

    return l_err_num;
}

/**
 * @brief dap_ledger_tx_check
 * @param a_ledger
 * @param a_tx
 * @return
 */
int dap_ledger_tx_add_check(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, size_t a_datum_size, dap_hash_fast_t *a_datum_hash)
{
    dap_return_val_if_fail(a_tx && a_ledger, DAP_LEDGER_CHECK_INVALID_ARGS);

    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    if (l_tx_size != a_datum_size) {
        log_it (L_WARNING, "Inconsistent datum TX: datum size %zu != tx size %zu", a_datum_size, l_tx_size);
        return DAP_LEDGER_CHECK_INVALID_SIZE;
    }
    int l_ret_check = s_tx_cache_check(a_ledger, a_tx, a_datum_hash, false, NULL, NULL, NULL, NULL, NULL, false);
    if(g_debug_ledger) {
        if (l_ret_check)
            log_it(L_NOTICE, "Ledger TX adding check not passed for TX %s: error %s",
                   dap_chain_hash_fast_to_str_static(a_datum_hash), dap_ledger_check_error_str(l_ret_check));
        else
            log_it(L_INFO, "Ledger TX adding check passed for TX %s", dap_chain_hash_fast_to_str_static(a_datum_hash));
    }

    return l_ret_check;
}

static struct json_object *s_wallet_info_json_collect(dap_ledger_t *a_ledger, dap_ledger_wallet_balance_t *a_bal)
{
    struct json_object *l_json = json_object_new_object();
    json_object_object_add(l_json, "class", json_object_new_string("Wallet"));
    struct json_object *l_network = json_object_new_object();
    json_object_object_add(l_network, "name", json_object_new_string(a_ledger->net->pub.name));
    char *pos = strrchr(a_bal->key, ' ');
    if (pos) {
        size_t l_addr_len = pos - a_bal->key;
        char *l_addr_str = DAP_NEW_STACK_SIZE(char, l_addr_len + 1);
        if ( !l_addr_str )
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        memcpy(l_addr_str, a_bal->key, pos - a_bal->key);
        *(l_addr_str + l_addr_len) = '\0';
        json_object_object_add(l_network, "address", json_object_new_string(l_addr_str));
    } else {
        json_object_object_add(l_network, "address", json_object_new_string("Unknown"));
    }
    struct json_object *l_token = json_object_new_object();
    json_object_object_add(l_token, "name", json_object_new_string(a_bal->token_ticker));
    const char *l_balance_coins, *l_balance_datoshi = dap_uint256_to_char(a_bal->balance, &l_balance_coins);
    json_object_object_add(l_token, "full_balance", json_object_new_string(l_balance_coins));
    json_object_object_add(l_token, "datoshi", json_object_new_string(l_balance_datoshi));
    json_object_object_add(l_network, "tokens", l_token);
    json_object_object_add(l_json, "networks", l_network);
    return l_json;
}

/**
 * @brief s_balance_cache_update
 * @param a_ledger
 * @param a_balance
 * @return
 */
static int s_balance_cache_update(dap_ledger_t *a_ledger, dap_ledger_wallet_balance_t *a_balance)
{
    if (PVT(a_ledger)->cached) {
        char *l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_BALANCES_STR);
        if (dap_global_db_set(l_gdb_group, a_balance->key, &a_balance->balance, sizeof(uint256_t), false, NULL, NULL)) {
            debug_if(g_debug_ledger, L_WARNING, "Ledger cache mismatch");
            return -1;
        }
        DAP_DELETE(l_gdb_group);
    }
    /* Notify the world*/
    if ( !dap_chain_net_get_load_mode(a_ledger->net) ) {
        struct json_object *l_json = s_wallet_info_json_collect(a_ledger, a_balance);
        dap_notify_server_send_mt(json_object_get_string(l_json));
        json_object_put(l_json);
    }
    return 0;
}

/**
 * @brief Add new transaction to the cache list
 * @param a_ledger
 * @param a_tx
 * @param a_tx_hash
 * @param a_from_threshold
 * @return return 1 OK, -1 error
 */
int dap_ledger_tx_add(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, bool a_from_threshold, dap_ledger_datum_iter_data_t *a_datum_index_data)
{
    if(!a_tx) {
        debug_if(g_debug_ledger, L_ERROR, "NULL tx detected");
        return -1;
    }
    int l_ret = 0;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_list_t *l_list_bound_items = NULL;
    dap_list_t *l_list_tx_out = NULL;
    char l_main_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX] = { '\0' };

    bool l_from_threshold = a_from_threshold;
    char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(a_tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));

    int l_ret_check;
    dap_chain_srv_uid_t l_tag =  { .uint64 = 0 };
    dap_chain_tx_tag_action_type_t l_action = DAP_CHAIN_TX_TAG_ACTION_UNKNOWN;

    if( (l_ret_check = s_tx_cache_check(a_ledger, a_tx, a_tx_hash, a_from_threshold,
                                                       &l_list_bound_items, &l_list_tx_out,
                                                       l_main_token_ticker, &l_tag, &l_action, false))) {
        if ((l_ret_check == DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS ||
                l_ret_check == DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION) &&
                l_ledger_pvt->threshold_enabled && !dap_chain_net_get_load_mode(a_ledger->net)) {
            if (!l_from_threshold)
                dap_ledger_pvt_threshold_txs_add(a_ledger, a_tx, a_tx_hash);
        } else {
            debug_if(g_debug_ledger, L_WARNING, "dap_ledger_tx_add() tx %s not passed the check: %s ", l_tx_hash_str,
                        dap_ledger_check_error_str(l_ret_check));
        }

        if ( l_list_bound_items )
            dap_list_free_full(l_list_bound_items, NULL);

        return l_ret_check;
    }
    debug_if(g_debug_ledger, L_DEBUG, "dap_ledger_tx_add() check passed for tx %s", l_tx_hash_str);
    if ( a_datum_index_data != NULL){
        dap_strncpy(a_datum_index_data->token_ticker, l_main_token_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
        a_datum_index_data->action = l_action;
        a_datum_index_data->uid = l_tag;
    }
    // Mark 'out' items in cache if they were used & delete previous transactions from cache if it need
    // find all bound pairs 'in' and 'out'
    size_t l_outs_used = dap_list_length(l_list_bound_items);

    dap_store_obj_t *l_cache_used_outs = NULL;
    char *l_ledger_cache_group = NULL;
    if (PVT(a_ledger)->cached) {
        l_cache_used_outs = DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(dap_store_obj_t) * (l_outs_used + 1));
        if ( !l_cache_used_outs ) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            l_ret = -1;
            goto FIN;
        }
        l_ledger_cache_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_TXS_STR);
    }
    const char *l_cur_token_ticker = NULL;

    // Update balance: deducts
    int l_spent_idx = 0;
    for (dap_list_t *it = l_list_bound_items; it; it = it->next) {
        dap_ledger_tx_bound_t *l_bound_item = it->data;
        dap_chain_tx_item_type_t l_type = l_bound_item->type;
        if (l_type == TX_ITEM_TYPE_IN || l_type == TX_ITEM_TYPE_IN_COND) {
            if (l_bound_item->prev_item->cache_data.n_outs <= l_bound_item->prev_item->cache_data.n_outs_used) {
                log_it(L_ERROR, "[!] Irrelevant prev tx: out items mismatch %d <= %d",
                       l_bound_item->prev_item->cache_data.n_outs, l_bound_item->prev_item->cache_data.n_outs_used);
                l_outs_used--;
                continue;
            }
            l_spent_idx++;
        }

        if ((l_type == TX_ITEM_TYPE_IN_EMS_LOCK || l_type == TX_ITEM_TYPE_IN_REWARD) &&
                !dap_ledger_pvt_token_supply_check_update(a_ledger, l_bound_item->token_item, l_bound_item->value, false))
            log_it(L_ERROR, "Insufficient supply for token %s", l_bound_item->token_item->ticker);

        switch (l_type) {
        case TX_ITEM_TYPE_IN_EMS:
            // Mark it as used with current tx hash
            l_bound_item->emission_item->tx_used_out = *a_tx_hash;
            dap_ledger_pvt_emission_cache_update(a_ledger, l_bound_item->emission_item);
            l_outs_used--; // Do not calc this output with tx used items
            continue;

        case TX_ITEM_TYPE_IN_EMS_LOCK:
            if (l_bound_item->stake_lock_item) { // Legacy stake lock emission
                // Mark it as used with current tx hash
                l_bound_item->stake_lock_item->tx_used_out = *a_tx_hash;
                s_ledger_stake_lock_cache_update(a_ledger, l_bound_item->stake_lock_item);
            }
            l_outs_used--; // Do not calc this output with tx used items
            continue;

        case TX_ITEM_TYPE_IN_REWARD: {
            dap_ledger_reward_item_t *l_item = DAP_NEW_Z(dap_ledger_reward_item_t);
            if (!l_item) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                l_ret = -1;
                goto FIN;
            }
            l_item->key = l_bound_item->reward_key;
            l_item->spender_tx = *a_tx_hash;
            pthread_rwlock_wrlock(&l_ledger_pvt->rewards_rwlock);
            HASH_ADD(hh, l_ledger_pvt->rewards, key, sizeof(l_item->key), l_item);
            pthread_rwlock_unlock(&l_ledger_pvt->rewards_rwlock);
        }
        l_outs_used--; // Do not calc this output with tx used items
        continue;

        case TX_ITEM_TYPE_IN: {
            dap_ledger_wallet_balance_t *wallet_balance = NULL;
            l_cur_token_ticker = l_bound_item->in.token_ticker;
            const char *l_addr_str = dap_chain_addr_to_str_static(&l_bound_item->in.addr_from);
            char *l_wallet_balance_key = dap_strjoin(" ", l_addr_str, l_cur_token_ticker, (char*)NULL);
            pthread_rwlock_rdlock(&PVT(a_ledger)->balance_accounts_rwlock);
            HASH_FIND_STR(PVT(a_ledger)->balance_accounts, l_wallet_balance_key, wallet_balance);
            pthread_rwlock_unlock(&PVT(a_ledger)->balance_accounts_rwlock);
            if (wallet_balance) {
                debug_if(g_debug_ledger, L_DEBUG, "SPEND %s from addr: %s",
                    dap_uint256_to_char(l_bound_item->value, NULL), l_wallet_balance_key);
                SUBTRACT_256_256(wallet_balance->balance, l_bound_item->value, &wallet_balance->balance);
                // Update the cache
                s_balance_cache_update(a_ledger, wallet_balance);
            } else {
                if(g_debug_ledger)
                    log_it(L_ERROR,"!!! Attempt to SPEND from some non-existent balance !!!: %s %s", l_addr_str, l_cur_token_ticker);
            }

            DAP_DELETE(l_wallet_balance_key);
        } break;

        case TX_ITEM_TYPE_IN_COND: { // all balance deducts performed with previous conditional transaction
            // Update service items if any
            dap_ledger_verificator_t *l_verificator = NULL;
            int l_tmp = l_bound_item->cond->header.subtype;
            pthread_rwlock_rdlock(&s_verificators_rwlock);
            HASH_FIND_INT(s_verificators, &l_tmp, l_verificator);
            pthread_rwlock_unlock(&s_verificators_rwlock);
            if (l_verificator && l_verificator->callback_added)
                l_verificator->callback_added(a_ledger, a_tx, a_tx_hash, l_bound_item->cond);
        } break;

        default:
            log_it(L_ERROR, "Unknown item type %d in ledger TX bound for IN part", l_type);
            break;
        }

        // add a used output
        dap_ledger_tx_item_t *l_prev_item_out = l_bound_item->prev_item;
        l_prev_item_out->cache_data.tx_hash_spent_fast[l_bound_item->prev_out_idx] = *a_tx_hash;
        l_prev_item_out->cache_data.n_outs_used++;
        if (PVT(a_ledger)->cached) {
            // mirror it in the cache
            size_t l_tx_size = dap_chain_datum_tx_get_size(l_prev_item_out->tx);
            size_t l_tx_cache_sz = l_tx_size + sizeof(l_prev_item_out->cache_data);
            byte_t *l_tx_cache = DAP_NEW_Z_SIZE(byte_t, l_tx_cache_sz);
            memcpy(l_tx_cache, &l_prev_item_out->cache_data, sizeof(l_prev_item_out->cache_data));
            memcpy(l_tx_cache + sizeof(l_prev_item_out->cache_data), l_prev_item_out->tx, l_tx_size);
            char *l_tx_i_hash = dap_chain_hash_fast_to_str_new(&l_prev_item_out->tx_hash_fast);
            l_cache_used_outs[l_spent_idx] = (dap_store_obj_t) {
                    .key        = l_tx_i_hash,
                    .value      = l_tx_cache,
                    .value_len  = l_tx_cache_sz,
                    .group      = l_ledger_cache_group,
            };
            l_cache_used_outs[l_spent_idx].timestamp = dap_nanotime_now();
        }
        // mark previous transactions as used with the extra timestamp
        if (l_prev_item_out->cache_data.n_outs_used == l_prev_item_out->cache_data.n_outs)
            l_prev_item_out->cache_data.ts_spent = a_tx->header.ts_created;
    }


    //Update balance : raise
    bool l_multichannel = false;
    bool l_cross_network = false;
    uint32_t l_outs_count = 0;
    for (dap_list_t *l_tx_out = l_list_tx_out; l_tx_out; l_tx_out = l_tx_out->next, l_outs_count++) {
        if (!l_tx_out->data) {
            log_it(L_ERROR, "Can't detect tx ticker or matching output, can't append balances cache");
            continue;
        }
        dap_chain_tx_item_type_t l_type = *(uint8_t *)l_tx_out->data;
        if (l_type == TX_ITEM_TYPE_OUT_COND) {
            // Update service items if any
            dap_chain_tx_out_cond_t *l_cond = (dap_chain_tx_out_cond_t *)l_tx_out->data;
            dap_ledger_verificator_t *l_verificator = NULL;
            int l_tmp = l_cond->header.subtype;
            pthread_rwlock_rdlock(&s_verificators_rwlock);
            HASH_FIND_INT(s_verificators, &l_tmp, l_verificator);
            pthread_rwlock_unlock(&s_verificators_rwlock);
            if (l_verificator && l_verificator->callback_added)
                l_verificator->callback_added(a_ledger, a_tx, a_tx_hash, NULL);
            continue;   // balance raise will be with next conditional transaction
        }

        dap_chain_addr_t *l_addr = NULL;
        uint256_t l_value = {};
        switch (l_type) {
        case TX_ITEM_TYPE_OUT: {
            dap_chain_tx_out_t *l_out_item_256 = (dap_chain_tx_out_t *)l_tx_out->data;
            l_addr = &l_out_item_256->addr;
            l_value = l_out_item_256->header.value;
            l_cur_token_ticker = l_main_token_ticker;
        } break;
        case TX_ITEM_TYPE_OUT_OLD: {
            dap_chain_tx_out_old_t *l_out_item = (dap_chain_tx_out_old_t *)l_tx_out->data;
            l_addr = &l_out_item->addr;
            l_value = GET_256_FROM_64(l_out_item->header.value);
            l_cur_token_ticker = l_main_token_ticker;
        } break;
        case TX_ITEM_TYPE_OUT_EXT: {
            dap_chain_tx_out_ext_t *l_out_item_ext_256 = (dap_chain_tx_out_ext_t *)l_tx_out->data;
            l_addr = &l_out_item_ext_256->addr;
            l_value = l_out_item_ext_256->header.value;
            l_cur_token_ticker = l_out_item_ext_256->token;
            l_multichannel = true;
        } break;
        default:
            log_it(L_ERROR, "Unknown item type %d", l_type);
            break;
        }
        if (!l_addr)
            continue;
        else if (l_addr->net_id.uint64 != a_ledger->net->pub.id.uint64 &&
                 !dap_chain_addr_is_blank(l_addr))
            l_cross_network = true;
        const char *l_addr_str = dap_chain_addr_to_str_static(l_addr);
        dap_ledger_wallet_balance_t *wallet_balance = NULL;
        char *l_wallet_balance_key = dap_strjoin(" ", l_addr_str, l_cur_token_ticker, (char*)NULL);
        debug_if(g_debug_ledger, L_DEBUG, "GOT %s to addr: %s",
            dap_uint256_to_char(l_value, NULL), l_wallet_balance_key);
        pthread_rwlock_rdlock(&l_ledger_pvt->balance_accounts_rwlock);
        HASH_FIND_STR(PVT(a_ledger)->balance_accounts, l_wallet_balance_key, wallet_balance);
        pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
        if (wallet_balance) {
            //if(g_debug_ledger)
            //    log_it(L_DEBUG, "Balance item is present in cache");
            SUM_256_256(wallet_balance->balance, l_value, &wallet_balance->balance);
            DAP_DELETE (l_wallet_balance_key);
            // Update the cache
            s_balance_cache_update(a_ledger, wallet_balance);
        } else {
            wallet_balance = DAP_NEW_Z(dap_ledger_wallet_balance_t);
            if (!wallet_balance) {
                log_it(L_CRITICAL, "Memory allocation error in s_load_cache_gdb_loaded_txs_callback");
                l_ret = -1;
                goto FIN;
            }
            wallet_balance->key = l_wallet_balance_key;
            strcpy(wallet_balance->token_ticker, l_cur_token_ticker);
            SUM_256_256(wallet_balance->balance, l_value, &wallet_balance->balance);
            if(g_debug_ledger)
                log_it(L_DEBUG, "Create new balance item: %s %s", l_addr_str, l_cur_token_ticker);
            pthread_rwlock_wrlock(&l_ledger_pvt->balance_accounts_rwlock);
            HASH_ADD_KEYPTR(hh, PVT(a_ledger)->balance_accounts, wallet_balance->key,
                            strlen(l_wallet_balance_key), wallet_balance);
            pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
            // Add it to cache
            s_balance_cache_update(a_ledger, wallet_balance);
        }
    }
    int l_err_num = 0;
    if (s_voting_callbacks.voting_callback) {
        if (l_tag.uint64 == DAP_CHAIN_TX_TAG_ACTION_VOTING)
            l_err_num = s_voting_callbacks.voting_callback(a_ledger, TX_ITEM_TYPE_VOTING, a_tx, a_tx_hash, true);
        else if (l_tag.uint64 == DAP_CHAIN_TX_TAG_ACTION_VOTE)
            l_err_num = s_voting_callbacks.voting_callback(a_ledger, TX_ITEM_TYPE_VOTE, a_tx, a_tx_hash, true);
    }
    assert(!l_err_num);

    // add transaction to the cache list
    dap_ledger_tx_item_t *l_tx_item = DAP_NEW_Z(dap_ledger_tx_item_t);
    if ( !l_tx_item ) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        l_ret = -1;
        goto FIN;
    }
    l_tx_item->tx_hash_fast = *a_tx_hash;
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    l_tx_item->tx = l_ledger_pvt->mapped ? a_tx : DAP_DUP_SIZE(a_tx, l_tx_size);
    l_tx_item->cache_data.n_outs = l_outs_count;
    l_tx_item->cache_data.tag = l_tag;
    l_tx_item->cache_data.action = l_action;
    dap_stpcpy(l_tx_item->cache_data.token_ticker, l_main_token_ticker);

    l_tx_item->cache_data.multichannel = l_multichannel;
    l_tx_item->ts_added = dap_nanotime_now();
    pthread_rwlock_wrlock(&l_ledger_pvt->ledger_rwlock);
    if (dap_chain_net_get_load_mode(a_ledger->net) || dap_chain_net_get_state(a_ledger->net) == NET_STATE_SYNC_CHAINS)
        HASH_ADD(hh, l_ledger_pvt->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_tx_item);
    else
        HASH_ADD_INORDER(hh, l_ledger_pvt->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t),
                         l_tx_item, s_sort_ledger_tx_item); // tx_hash_fast: name of key field
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    // Callable callback
    dap_list_t *l_notifier;
    DL_FOREACH(PVT(a_ledger)->tx_add_notifiers, l_notifier) {
        dap_ledger_tx_notifier_t *l_notify = (dap_ledger_tx_notifier_t*)l_notifier->data;
        l_notify->callback(l_notify->arg, a_ledger, l_tx_item->tx, DAP_LEDGER_NOTIFY_OPCODE_ADDED);
    }
    if (l_cross_network) {
        dap_list_t *l_notifier;
        DL_FOREACH(PVT(a_ledger)->bridged_tx_notifiers, l_notifier) {
            dap_ledger_bridged_tx_notifier_t *l_notify = l_notifier->data;
            l_notify->callback(a_ledger, a_tx, a_tx_hash, l_notify->arg, DAP_LEDGER_NOTIFY_OPCODE_ADDED);
        }
    }
    if (PVT(a_ledger)->cached) {
        // Add it to cache
        size_t l_tx_cache_sz = l_tx_size + sizeof(l_tx_item->cache_data);
        uint8_t *l_tx_cache = DAP_NEW_STACK_SIZE(uint8_t, l_tx_cache_sz);
        memcpy(l_tx_cache, &l_tx_item->cache_data, sizeof(l_tx_item->cache_data));
        memcpy(l_tx_cache + sizeof(l_tx_item->cache_data), a_tx, l_tx_size);
        l_cache_used_outs[0] = (dap_store_obj_t) {
                .key        = l_tx_hash_str,
                .value      = l_tx_cache,
                .value_len  = l_tx_cache_sz,
                .group      = l_ledger_cache_group,
        };
        l_cache_used_outs[0].timestamp = dap_nanotime_now();
        // Apply it with single DB transaction
        if (dap_global_db_set_raw(l_cache_used_outs, l_outs_used + 1, NULL, NULL))
            debug_if(g_debug_ledger, L_WARNING, "Ledger cache mismatch");
    }
    if (!a_from_threshold && l_ledger_pvt->threshold_enabled)
        dap_ledger_pvt_threshold_txs_proc(a_ledger);
FIN:
    if (l_list_bound_items)
        dap_list_free_full(l_list_bound_items, NULL);
    if (l_list_tx_out)
        dap_list_free(l_list_tx_out);
    if (PVT(a_ledger)->cached) {
        if (l_cache_used_outs) {
            for (size_t i = 1; i <= l_outs_used; i++) {
                DAP_DEL_Z(l_cache_used_outs[i].key);
                DAP_DEL_Z(l_cache_used_outs[i].value);
            }
        }
        DAP_DEL_Z(l_cache_used_outs);
        DAP_DEL_Z(l_ledger_cache_group);
    }
    return l_ret;
}

/**
 * @brief Remove transaction from the cache list
 * @param a_ledger
 * @param a_tx
 * @param a_tx_hash
 * @param a_from_threshold
 * @return return 1 OK, -1 error
 */
int dap_ledger_tx_remove(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash)
{
    int l_ret = 0;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_list_t *l_list_bound_items = NULL;
    dap_list_t *l_list_tx_out = NULL;
    dap_chain_srv_uid_t l_tag =  { .uint64 = 0 };
    char l_main_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX] = { '\0' };

    char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(a_tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));

    // Get boundary items list into l_list_bound_items
    // Get tx outs list into l_list_tx_out
    int l_ret_check;
    if( (l_ret_check = s_tx_cache_check(a_ledger, a_tx, a_tx_hash, false,
                                                       &l_list_bound_items, &l_list_tx_out,
                                                       l_main_token_ticker, &l_tag, NULL, true))) {
        debug_if(g_debug_ledger, L_WARNING, "dap_ledger_tx_remove() tx %s not passed the check: %s ", l_tx_hash_str,
                    dap_ledger_check_error_str(l_ret_check));
        return l_ret_check;
    }

    dap_ledger_tx_item_t *l_ledger_item = NULL;
    pthread_rwlock_rdlock(&PVT(a_ledger)->ledger_rwlock);
    HASH_FIND(hh, PVT(a_ledger)->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_ledger_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
    if (l_ledger_item && l_ledger_item->cache_data.n_outs_used != 0) {     // transaction already present in the cache list
        return DAP_LEDGER_TX_CHECK_OUT_ITEM_ALREADY_USED;
    }

    // find all bound pairs 'in' and 'out'
    size_t l_outs_used = dap_list_length(l_list_bound_items);

    dap_store_obj_t *l_cache_used_outs = NULL;
    char *l_ledger_cache_group = NULL;
    if (PVT(a_ledger)->cached) {
        l_cache_used_outs = DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(dap_store_obj_t) * (l_outs_used));
        if ( !l_cache_used_outs ) {
            log_it(L_CRITICAL, "Memory allocation error");
            l_ret = -1;
            goto FIN;
        }
        l_ledger_cache_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_TXS_STR);
    }
    const char *l_cur_token_ticker = NULL;

    // Update balance : raise all bound items to balances
    int l_spent_idx = 0;
    for (dap_list_t *it = l_list_bound_items; it; it = it->next) {
        dap_ledger_tx_bound_t *l_bound_item = it->data;
        dap_chain_tx_item_type_t l_type = l_bound_item->type;
        if ((l_type == TX_ITEM_TYPE_IN_EMS_LOCK || l_type == TX_ITEM_TYPE_IN_REWARD) &&
                !dap_ledger_pvt_token_supply_check_update(a_ledger, l_bound_item->token_item, l_bound_item->value, true))
            log_it(L_ERROR, "Insufficient supply for token %s", l_bound_item->token_item->ticker);

        switch (l_type) {
        case TX_ITEM_TYPE_IN_EMS:
            // Mark it as unused
            memset(&(l_bound_item->emission_item->tx_used_out), 0, sizeof(dap_hash_fast_t));
            dap_ledger_pvt_emission_cache_update(a_ledger, l_bound_item->emission_item);
            l_outs_used--; // Do not calc this output with tx used items
            continue;

        case TX_ITEM_TYPE_IN_EMS_LOCK:
            if (l_bound_item->stake_lock_item) { // Legacy stake lock emission
                // Mark it as used with current tx hash
                memset(&(l_bound_item->stake_lock_item->tx_used_out), 0, sizeof(dap_hash_fast_t));
                s_ledger_stake_lock_cache_update(a_ledger, l_bound_item->stake_lock_item);
            }
            l_outs_used--; // Do not calc this output with tx used items
            continue;

        case TX_ITEM_TYPE_IN_REWARD: {
            dap_ledger_reward_item_t *l_item = NULL;
            pthread_rwlock_wrlock(&l_ledger_pvt->rewards_rwlock);
            HASH_FIND(hh, l_ledger_pvt->rewards, &l_bound_item->reward_key, sizeof(l_bound_item->reward_key), l_item);
            if(l_item){
                HASH_DEL(l_ledger_pvt->rewards, l_item);
                DAP_DEL_Z(l_item);
            }
            pthread_rwlock_unlock(&l_ledger_pvt->rewards_rwlock);
        }
        l_outs_used--; // Do not calc this output with tx used items
        continue;

        case TX_ITEM_TYPE_IN: {
            dap_ledger_wallet_balance_t *wallet_balance = NULL;
            l_cur_token_ticker = l_bound_item->in.token_ticker;
            const char *l_addr_str = dap_chain_addr_to_str_static(&l_bound_item->in.addr_from);
            char *l_wallet_balance_key = dap_strjoin(" ", l_addr_str, l_cur_token_ticker, (char*)NULL);
            pthread_rwlock_rdlock(&PVT(a_ledger)->balance_accounts_rwlock);
            HASH_FIND_STR(PVT(a_ledger)->balance_accounts, l_wallet_balance_key, wallet_balance);
            pthread_rwlock_unlock(&PVT(a_ledger)->balance_accounts_rwlock);
            if (wallet_balance) {
                if(g_debug_ledger) {
                    char *l_balance = dap_chain_balance_datoshi_print(l_bound_item->value);
                    log_it(L_DEBUG,"REFUND %s from addr: %s because tx was removed.", l_balance, l_wallet_balance_key);
                    DAP_DELETE(l_balance);
                }
                SUM_256_256(wallet_balance->balance, l_bound_item->value, &wallet_balance->balance);
                // Update the cache
                s_balance_cache_update(a_ledger, wallet_balance);
            } else {
                if(g_debug_ledger)
                    log_it(L_ERROR,"!!! Attempt to SPEND from some non-existent balance !!!: %s %s", l_addr_str, l_cur_token_ticker);
            }
            DAP_DELETE(l_wallet_balance_key);
        } break;

        case TX_ITEM_TYPE_IN_COND: { // all balance deducts performed with previous conditional transaction
            // Update service items if any
            dap_ledger_verificator_t *l_verificator = NULL;
            int l_tmp = l_bound_item->cond->header.subtype;
            pthread_rwlock_rdlock(&s_verificators_rwlock);
            HASH_FIND_INT(s_verificators, &l_tmp, l_verificator);
            pthread_rwlock_unlock(&s_verificators_rwlock);
            if (l_verificator && l_verificator->callback_deleted)
                l_verificator->callback_deleted(a_ledger, a_tx, l_bound_item->cond);
        } break;

        default:
            log_it(L_ERROR, "Unknown item type %d in ledger TX bound for IN part", l_type);
            break;
        }

        // add a used output
        dap_ledger_tx_item_t *l_prev_item_out = l_bound_item->prev_item;
        memset(&(l_prev_item_out->cache_data.tx_hash_spent_fast[l_bound_item->prev_out_idx]), 0, sizeof(dap_hash_fast_t));
        l_prev_item_out->cache_data.n_outs_used--;
        if (PVT(a_ledger)->cached) {
            // mirror it in the cache
            size_t l_tx_size = dap_chain_datum_tx_get_size(l_prev_item_out->tx);
            size_t l_tx_cache_sz = l_tx_size + sizeof(l_prev_item_out->cache_data);
            byte_t *l_tx_cache = DAP_NEW_Z_SIZE(byte_t, l_tx_cache_sz);
            memcpy(l_tx_cache, &l_prev_item_out->cache_data, sizeof(l_prev_item_out->cache_data));
            memcpy(l_tx_cache + sizeof(l_prev_item_out->cache_data), l_prev_item_out->tx, l_tx_size);
            char *l_tx_i_hash = dap_chain_hash_fast_to_str_new(&l_prev_item_out->tx_hash_fast);
            l_cache_used_outs[l_spent_idx] = (dap_store_obj_t) {
                    .key        = l_tx_i_hash,
                    .value      = l_tx_cache,
                    .value_len  = l_tx_cache_sz,
                    .group      = l_ledger_cache_group
            };
            l_cache_used_outs[l_spent_idx].timestamp = 0;
        }
        // mark previous transactions as used with the extra timestamp
        if(l_prev_item_out->cache_data.n_outs_used != l_prev_item_out->cache_data.n_outs)
            l_prev_item_out->cache_data.ts_spent = 0;

        if (l_type == TX_ITEM_TYPE_IN || l_type == TX_ITEM_TYPE_IN_COND) {
            l_spent_idx++;
        }
    }

    // Update balance: deducts all outs from balances
    bool l_cross_network = false;
    for (dap_list_t *l_tx_out = l_list_tx_out; l_tx_out; l_tx_out = dap_list_next(l_tx_out)) {
        if (!l_tx_out->data) {
            debug_if(g_debug_ledger, L_WARNING, "Can't detect tx ticker or matching output, can't append balances cache");
            continue;
        }
        dap_chain_tx_item_type_t l_type = *(uint8_t *)l_tx_out->data;
        if (l_type == TX_ITEM_TYPE_OUT_COND) {
            // Update service items if any
            dap_chain_tx_out_cond_t *l_cond = (dap_chain_tx_out_cond_t *)l_tx_out->data;
            dap_ledger_verificator_t *l_verificator = NULL;
            int l_tmp = l_cond->header.subtype;
            pthread_rwlock_rdlock(&s_verificators_rwlock);
            HASH_FIND_INT(s_verificators, &l_tmp, l_verificator);
            pthread_rwlock_unlock(&s_verificators_rwlock);
            if (l_verificator && l_verificator->callback_deleted)
                l_verificator->callback_deleted(a_ledger, a_tx, NULL);
            continue;   // balance raise will be with next conditional transaction
        }

        dap_chain_addr_t *l_addr = NULL;
        uint256_t l_value = {};
        switch (l_type) {
        case TX_ITEM_TYPE_OUT: {
            dap_chain_tx_out_t *l_out_item_256 = (dap_chain_tx_out_t *)l_tx_out->data;
            l_addr = &l_out_item_256->addr;
            l_value = l_out_item_256->header.value;
            l_cur_token_ticker = l_main_token_ticker;
        } break;
        case TX_ITEM_TYPE_OUT_OLD: {
            dap_chain_tx_out_old_t *l_out_item = (dap_chain_tx_out_old_t *)l_tx_out->data;
            l_addr = &l_out_item->addr;
            l_value = GET_256_FROM_64(l_out_item->header.value);
            l_cur_token_ticker = l_main_token_ticker;
        } break;
        case TX_ITEM_TYPE_OUT_EXT: {
            dap_chain_tx_out_ext_t *l_out_item_ext_256 = (dap_chain_tx_out_ext_t *)l_tx_out->data;
            l_addr = &l_out_item_ext_256->addr;
            l_value = l_out_item_ext_256->header.value;
            l_cur_token_ticker = l_out_item_ext_256->token;
        } break;
        default:
            log_it(L_DEBUG, "Unknown item type %d", l_type);
            break;
        }
        if (!l_addr)
            continue;
        else if (l_addr->net_id.uint64 != a_ledger->net->pub.id.uint64 &&
                 !dap_chain_addr_is_blank(l_addr))
            l_cross_network = true;
        const char *l_addr_str = dap_chain_addr_to_str_static(l_addr);
        dap_ledger_wallet_balance_t *wallet_balance = NULL;
        char *l_wallet_balance_key = dap_strjoin(" ", l_addr_str, l_cur_token_ticker, (char*)NULL);
        if(g_debug_ledger) {
            char *l_balance = dap_chain_balance_datoshi_print(l_value);
            log_it(L_DEBUG, "UNDO %s from addr: %s", l_balance, l_wallet_balance_key);
            DAP_DELETE(l_balance);
        }
        pthread_rwlock_rdlock(&l_ledger_pvt->balance_accounts_rwlock);
        HASH_FIND_STR(PVT(a_ledger)->balance_accounts, l_wallet_balance_key, wallet_balance);
        pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
        if (wallet_balance) {
            //if(g_debug_ledger)
            //    log_it(L_DEBUG, "Balance item is present in cache");
            SUBTRACT_256_256(wallet_balance->balance, l_value, &wallet_balance->balance);
            DAP_DELETE (l_wallet_balance_key);
            // Update the cache
            s_balance_cache_update(a_ledger, wallet_balance);
        } else {
            log_it(L_CRITICAL, "Wallet is not presented in cache. Can't substract out value from balance.");
        }
    }

    if (s_voting_callbacks.voting_delete_callback) {
        if (l_tag.uint64 == DAP_CHAIN_TX_TAG_ACTION_VOTING)
            s_voting_callbacks.voting_delete_callback(a_ledger, TX_ITEM_TYPE_VOTING, a_tx);
        else if (l_tag.uint64 == DAP_CHAIN_TX_TAG_ACTION_VOTE)
            s_voting_callbacks.voting_delete_callback(a_ledger, TX_ITEM_TYPE_VOTE, a_tx);
    }

    // remove transaction from ledger
    dap_ledger_tx_item_t *l_tx_item = NULL;
    pthread_rwlock_wrlock(&l_ledger_pvt->ledger_rwlock);
    HASH_FIND(hh, l_ledger_pvt->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_item);
    if (l_tx_item)
        HASH_DEL(l_ledger_pvt->ledger_items, l_tx_item);
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);

    // Callable callback
    dap_list_t *l_notifier;
    DL_FOREACH(PVT(a_ledger)->tx_add_notifiers, l_notifier) {
        dap_ledger_tx_notifier_t *l_notify = (dap_ledger_tx_notifier_t*)l_notifier->data;
        l_notify->callback(l_notify->arg, a_ledger, l_tx_item->tx, DAP_LEDGER_NOTIFY_OPCODE_DELETED);
    }
    if (l_cross_network) {
        dap_list_t *l_notifier;
        DL_FOREACH(PVT(a_ledger)->bridged_tx_notifiers, l_notifier) {
            dap_ledger_bridged_tx_notifier_t *l_notify = l_notifier->data;
            l_notify->callback(a_ledger, a_tx, a_tx_hash, l_notify->arg, DAP_LEDGER_NOTIFY_OPCODE_DELETED);
        }
    }

    if (PVT(a_ledger)->cached) {
        // Add it to cache
        dap_global_db_del_sync(l_ledger_cache_group, l_tx_hash_str);
        // Apply it with single DB transaction
        if (dap_global_db_set_raw(l_cache_used_outs, l_outs_used, NULL, NULL))
            debug_if(g_debug_ledger, L_WARNING, "Ledger cache mismatch");
    }
FIN:
    if (l_list_bound_items)
        dap_list_free_full(l_list_bound_items, NULL);
    if (l_list_tx_out)
        dap_list_free(l_list_tx_out);
    if (PVT(a_ledger)->cached) {
        if (l_cache_used_outs) {
            for (size_t i = 1; i < l_outs_used; i++) {
                DAP_DEL_Z(l_cache_used_outs[i].key);
                DAP_DEL_Z(l_cache_used_outs[i].value);
            }
        }
        DAP_DEL_Z(l_cache_used_outs);
        DAP_DEL_Z(l_ledger_cache_group);
    }
    return l_ret;
}

int dap_ledger_tx_load(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_hash_fast_t *a_tx_hash, dap_ledger_datum_iter_data_t *a_datum_index_data)
{
#ifndef DAP_LEDGER_TEST
    if (dap_chain_net_get_load_mode(a_ledger->net)) {
        if (PVT(a_ledger)->cache_tx_check_callback)
            PVT(a_ledger)->cache_tx_check_callback(a_ledger, a_tx_hash);
        dap_ledger_tx_item_t *l_tx_item = NULL;
        unsigned l_hash_value;
        HASH_VALUE(a_tx_hash, sizeof(dap_chain_hash_fast_t), l_hash_value);
        pthread_rwlock_rdlock(&PVT(a_ledger)->ledger_rwlock);
        HASH_FIND_BYHASHVALUE(hh, PVT(a_ledger)->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_hash_value, l_tx_item);
        pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
        if (l_tx_item)
            return DAP_LEDGER_CHECK_ALREADY_CACHED;
    }
#endif
    return dap_ledger_tx_add(a_ledger, a_tx, a_tx_hash, false, a_datum_index_data);
}



static void s_ledger_stake_lock_cache_update(dap_ledger_t *a_ledger, dap_ledger_stake_lock_item_t *a_stake_lock_item)
{
    if (!PVT(a_ledger)->cached)
        return;
    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&a_stake_lock_item->tx_for_stake_lock_hash, l_hash_str, sizeof(l_hash_str));
    char *l_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_STAKE_LOCK_STR);
    if (dap_global_db_set(l_group, l_hash_str, &a_stake_lock_item->tx_used_out, sizeof(dap_hash_fast_t), false, NULL, NULL))
        log_it(L_WARNING, "Ledger cache mismatch");
    DAP_DEL_Z(l_group);
}

int dap_ledger_emission_for_stake_lock_item_add(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_tx_hash)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_stake_lock_item_t *l_new_stake_lock_emission = NULL;
    pthread_rwlock_rdlock(&l_ledger_pvt->stake_lock_rwlock);
    HASH_FIND(hh, l_ledger_pvt->emissions_for_stake_lock, a_tx_hash, sizeof(dap_hash_fast_t),
              l_new_stake_lock_emission);
    pthread_rwlock_unlock(&l_ledger_pvt->stake_lock_rwlock);
    if (l_new_stake_lock_emission) {
        return -1;
    }
    l_new_stake_lock_emission = DAP_NEW_Z(dap_ledger_stake_lock_item_t);
    if (!l_new_stake_lock_emission) {
        if (g_debug_ledger) {
            log_it(L_ERROR, "Error: memory allocation when try adding item 'dap_ledger_stake_lock_item_t' to hash-table");
        }
        return -13;
    }
    l_new_stake_lock_emission->tx_for_stake_lock_hash = *a_tx_hash;
    pthread_rwlock_wrlock(&l_ledger_pvt->stake_lock_rwlock);
    HASH_ADD(hh, l_ledger_pvt->emissions_for_stake_lock, tx_for_stake_lock_hash, sizeof(dap_chain_hash_fast_t), l_new_stake_lock_emission);
    pthread_rwlock_unlock(&l_ledger_pvt->stake_lock_rwlock);

    s_ledger_stake_lock_cache_update(a_ledger, l_new_stake_lock_emission);

    return 0;

}

static dap_ledger_stake_lock_item_t *s_emissions_for_stake_lock_item_find(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_token_emission_hash)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_stake_lock_item_t *l_new_stake_lock_emission = NULL;
    pthread_rwlock_rdlock(&l_ledger_pvt->stake_lock_rwlock);
    HASH_FIND(hh, l_ledger_pvt->emissions_for_stake_lock, a_token_emission_hash, sizeof(dap_chain_hash_fast_t),
              l_new_stake_lock_emission);
    pthread_rwlock_unlock(&l_ledger_pvt->stake_lock_rwlock);
    return l_new_stake_lock_emission;
}

/**
 * @brief dap_ledger_tx_get_token_ticker_by_hash
 * @param a_ledger
 * @param a_tx_hash
 * @return
 */
const char *dap_ledger_tx_get_token_ticker_by_hash(dap_ledger_t *a_ledger,dap_chain_hash_fast_t *a_tx_hash)
{
    if(!a_ledger || !a_tx_hash)
        return NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);

    if ( dap_hash_fast_is_blank(a_tx_hash) )
        return NULL;

    dap_ledger_tx_item_t *l_item = NULL;
    unsigned l_hash_value;
    HASH_VALUE(a_tx_hash, sizeof(*a_tx_hash), l_hash_value);
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    HASH_FIND_BYHASHVALUE(hh, l_ledger_pvt->ledger_items, a_tx_hash, sizeof(*a_tx_hash), l_hash_value, l_item);
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    return l_item ? l_item->cache_data.token_ticker : NULL;
}

/**
 * Get transaction in the cache by hash
 *
 * return transaction, or NULL if transaction not found in the cache
 */
static dap_chain_datum_tx_t *s_tx_find_by_hash(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_tx_hash, dap_ledger_tx_item_t **a_item_out, bool a_unspent_only)
{
    if ( !a_tx_hash || dap_hash_fast_is_blank(a_tx_hash) )
        return NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_chain_datum_tx_t *l_tx_ret = NULL;
    dap_ledger_tx_item_t *l_tx_item = NULL;
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    HASH_FIND(hh, l_ledger_pvt->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_item);
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    if(l_tx_item) {
        if (!a_unspent_only || !l_tx_item->cache_data.ts_spent) {
            l_tx_ret = l_tx_item->tx;
            if(a_item_out)
                *a_item_out = l_tx_item;
        }
    }
    return l_tx_ret;
}

dap_chain_datum_tx_t *dap_ledger_tx_find_by_hash(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_tx_hash)
{
   return s_tx_find_by_hash(a_ledger, a_tx_hash, NULL, false);
}

dap_chain_datum_tx_t *dap_ledger_tx_unspent_find_by_hash(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash)
{
    return s_tx_find_by_hash(a_ledger, a_tx_hash, NULL, true);
}

dap_hash_fast_t dap_ledger_get_first_chain_tx_hash(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_subtype_t a_cond_type, dap_chain_hash_fast_t *a_tx_hash)
{
    dap_return_val_if_fail(a_ledger && a_tx_hash, (dap_hash_fast_t) {});
    dap_hash_fast_t l_hash = *a_tx_hash, l_hash_tmp;
    dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_ledger, a_tx_hash);
    byte_t *l_iter = l_prev_tx->tx_items;
    while (( l_iter = dap_chain_datum_tx_item_get(l_prev_tx, NULL, l_iter, TX_ITEM_TYPE_IN_COND, NULL) )) {
        l_hash_tmp =  ((dap_chain_tx_in_cond_t *)l_iter)->header.tx_prev_hash;
        if ( dap_hash_fast_is_blank(&l_hash_tmp) )
            return l_hash_tmp;
        if (( l_prev_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_hash_tmp) ) &&
                ( dap_chain_datum_tx_out_cond_get(l_prev_tx, a_cond_type, NULL) )) {
            l_hash = l_hash_tmp;
            l_iter = l_prev_tx->tx_items;
        }
    }
    return l_hash;
}

dap_hash_fast_t dap_ledger_get_final_chain_tx_hash(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_subtype_t a_cond_type, dap_chain_hash_fast_t *a_tx_hash)
{
    dap_chain_hash_fast_t l_hash = { }, l_hash_tmp;
    if (!a_ledger || !a_tx_hash || dap_hash_fast_is_blank(a_tx_hash))
        return l_hash;

    dap_chain_datum_tx_t *l_tx = NULL;
    l_hash = *a_tx_hash;
    int l_out_num = 0;
    dap_ledger_tx_item_t *l_item = NULL;
    while (( l_tx = s_tx_find_by_hash(a_ledger, &l_hash, &l_item, false) )) {
        if ( !dap_chain_datum_tx_out_cond_get(l_tx, a_cond_type, &l_out_num)
            || dap_hash_fast_is_blank(&l_item->cache_data.tx_hash_spent_fast[l_out_num]))
            break;

        l_hash = l_item->cache_data.tx_hash_spent_fast[l_out_num];
    }
    return l_hash;
}

/**
 * Check whether used 'out' items (local function)
 */
static bool s_ledger_tx_hash_is_used_out_item(dap_ledger_tx_item_t *a_item, int a_idx_out, dap_hash_fast_t *a_out_spender_hash)
{
    if (!a_item || !a_item->cache_data.n_outs) {
        //log_it(L_DEBUG, "list_cached_item is NULL");
        return true;
    }
    if(a_idx_out >= MAX_OUT_ITEMS) {
        if(g_debug_ledger)
            log_it(L_ERROR, "Too big index(%d) of 'out' items (max=%d)", a_idx_out, MAX_OUT_ITEMS);
    }
    assert(a_idx_out < MAX_OUT_ITEMS);
    // if there are used 'out' items
    if ((a_item->cache_data.n_outs_used > 0) && !dap_hash_fast_is_blank(&(a_item->cache_data.tx_hash_spent_fast[a_idx_out]))) {
        if (a_out_spender_hash)
            *a_out_spender_hash = a_item->cache_data.tx_hash_spent_fast[a_idx_out];
        return true;
    }
    return false;
}

/**
 * Check whether used 'out' items
 */
bool dap_ledger_tx_hash_is_used_out_item(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash, int a_idx_out, dap_hash_fast_t *a_out_spender)
{
    dap_ledger_tx_item_t *l_item_out = NULL;
    /*dap_chain_datum_tx_t *l_tx =*/ s_tx_find_by_hash(a_ledger, a_tx_hash, &l_item_out, false);
    return l_item_out ? s_ledger_tx_hash_is_used_out_item(l_item_out, a_idx_out, a_out_spender) : true;
}

void dap_ledger_tx_add_notify(dap_ledger_t *a_ledger, dap_ledger_tx_add_notify_t a_callback, void *a_arg)
{
    dap_return_if_fail(a_ledger && a_callback);
    dap_ledger_tx_notifier_t *l_notifier;
    DAP_NEW_Z_RET(l_notifier, dap_ledger_tx_notifier_t, NULL);
    *l_notifier = (dap_ledger_tx_notifier_t) { .callback = a_callback, .arg = a_arg };
    PVT(a_ledger)->tx_add_notifiers = dap_list_append(PVT(a_ledger)->tx_add_notifiers, l_notifier);
}

void dap_ledger_bridged_tx_notify_add(dap_ledger_t *a_ledger, dap_ledger_bridged_tx_notify_t a_callback, void *a_arg)
{
    dap_return_if_fail(a_ledger && a_callback);
    dap_ledger_bridged_tx_notifier_t *l_notifier;
    DAP_NEW_Z_RET(l_notifier, dap_ledger_bridged_tx_notifier_t, NULL);
    *l_notifier = (dap_ledger_bridged_tx_notifier_t) { .callback = a_callback, .arg = a_arg };
    PVT(a_ledger)->bridged_tx_notifiers = dap_list_append(PVT(a_ledger)->bridged_tx_notifiers , l_notifier);
}

const char *dap_ledger_tx_calculate_main_ticker(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, int *a_ledger_rc)
{
    static _Thread_local char s_main_ticker[DAP_CHAIN_TICKER_SIZE_MAX] = { '\0' };
    dap_hash_fast_t l_tx_hash = dap_chain_node_datum_tx_calc_hash(a_tx);
    int l_rc = s_tx_cache_check(a_ledger, a_tx, &l_tx_hash, false, NULL, NULL, s_main_ticker, NULL, NULL, false);
    if (l_rc == DAP_LEDGER_CHECK_ALREADY_CACHED)
        dap_strncpy( s_main_ticker, dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_tx_hash), DAP_CHAIN_TICKER_SIZE_MAX );
    if (a_ledger_rc)
        *a_ledger_rc = l_rc;
    return s_main_ticker;
}

// Add new verificator callback with associated subtype. Returns 1 if callback replaced, -1 error, overwise returns 0
int dap_ledger_verificator_add(dap_chain_tx_out_cond_subtype_t a_subtype, dap_ledger_verificator_callback_t a_callback, dap_ledger_updater_callback_t a_callback_added, dap_ledger_delete_callback_t a_callback_deleted)
{
    dap_ledger_verificator_t *l_new_verificator = NULL;
    int l_tmp = (int)a_subtype;
    pthread_rwlock_rdlock(&s_verificators_rwlock);
    HASH_FIND_INT(s_verificators, &l_tmp, l_new_verificator);
    pthread_rwlock_unlock(&s_verificators_rwlock);
    if (l_new_verificator) {
        l_new_verificator->callback = a_callback;
        return 1;
    }
    l_new_verificator = DAP_NEW(dap_ledger_verificator_t);
    if (!l_new_verificator) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -1;
    }
    l_new_verificator->subtype = (int)a_subtype;
    l_new_verificator->callback = a_callback;
    l_new_verificator->callback_added = a_callback_added;
    l_new_verificator->callback_deleted = a_callback_deleted;
    pthread_rwlock_wrlock(&s_verificators_rwlock);
    HASH_ADD_INT(s_verificators, subtype, l_new_verificator);
    pthread_rwlock_unlock(&s_verificators_rwlock);
    return 0;
}

int dap_ledger_voting_verificator_add(dap_ledger_voting_callback_t a_callback, dap_ledger_voting_delete_callback_t a_callback_delete)
{
    if (!a_callback)
        return -1;

    if (!s_voting_callbacks.voting_callback || !s_voting_callbacks.voting_delete_callback){
        s_voting_callbacks.voting_callback = a_callback;
        s_voting_callbacks.voting_delete_callback = a_callback_delete;
        return 1;
    }

    s_voting_callbacks.voting_callback = a_callback;
    s_voting_callbacks.voting_delete_callback = a_callback_delete;
    return 0;
}

int dap_ledger_tax_callback_set(dap_ledger_tax_callback_t a_callback)
{
    if (s_tax_callback)
        return -1;
    s_tax_callback = a_callback;
    return 0;
}

void dap_ledger_set_cache_tx_check_callback(dap_ledger_t *a_ledger, dap_ledger_cache_tx_check_callback_t a_callback)
{
    PVT(a_ledger)->cache_tx_check_callback = a_callback;
}

uint256_t dap_ledger_calc_balance_full(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr, const char *a_token_ticker)
{
    uint256_t balance = uint256_0;

    if(!a_addr || dap_chain_addr_check_sum(a_addr))
        return balance;

    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_tx_item_t *l_iter_current, *l_item_tmp;
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    HASH_ITER(hh, l_ledger_pvt->ledger_items , l_iter_current, l_item_tmp)
    {
        dap_chain_datum_tx_t *l_cur_tx = l_iter_current->tx;
        // Get 'out' items from transaction
        int l_out_idx = 0;
        byte_t *it; size_t l_size;
        TX_ITEM_ITER_TX(it, l_size, l_cur_tx) {
            if ( l_out_idx > MAX_OUT_ITEMS )
                return log_it(L_ERROR, "Number of 'out' items exeeds max number %d", MAX_OUT_ITEMS), uint256_0;
            uint256_t l_add = { };
            dap_chain_addr_t l_out_addr = { };
            switch (*it) {
            case TX_ITEM_TYPE_OUT_OLD: {
                dap_chain_tx_out_old_t *l_tx_out = (dap_chain_tx_out_old_t*)it;
                l_add = dap_chain_uint256_from(l_tx_out->header.value);
                l_out_addr = l_tx_out->addr;
            } break;
            case TX_ITEM_TYPE_OUT: {
                dap_chain_tx_out_t *l_tx_out = (dap_chain_tx_out_t*)it;
                l_add = l_tx_out->header.value;
                l_out_addr = l_tx_out->addr;
            } break;
            case TX_ITEM_TYPE_OUT_EXT: {
                dap_chain_tx_out_ext_t *l_tx_out = (dap_chain_tx_out_ext_t*)it;
                l_add = l_tx_out->header.value;
                l_out_addr = l_tx_out->addr;
            } break;
            case TX_ITEM_TYPE_OUT_COND:
                ++l_out_idx;
            default:
                continue;
            }
            ++l_out_idx;
            if (    !dap_strcmp( a_token_ticker, l_iter_current->cache_data.token_ticker )  // Tokens match
                &&  !dap_chain_addr_compare( a_addr, &l_out_addr )                          // Addresses match
                &&  !s_ledger_tx_hash_is_used_out_item( l_iter_current, l_out_idx, NULL )   // Output is unused
                &&  !dap_chain_datum_tx_verify_sign(l_cur_tx)                               // Signs are valid
                ) SUM_256_256(balance, l_add, &balance);
        }
    }
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    return balance;
}

static int s_compare_balances(dap_ledger_hardfork_balances_t *a_list1, dap_ledger_hardfork_balances_t *a_list2)
{
    int ret = memcmp(&a_list1->addr, &a_list2->addr, sizeof(dap_chain_addr_t));
    return ret ? ret : memcmp(a_list1->ticker, a_list2->ticker, DAP_CHAIN_TICKER_SIZE_MAX);
}

static int s_aggregate_out(dap_ledger_hardfork_balances_t **a_out_list, const char *a_ticker, dap_chain_addr_t *a_addr, uint256_t a_value)
{
    dap_ledger_hardfork_balances_t l_new_balance = { .addr = *a_addr, .value = a_value };
    memcpy(l_new_balance.ticker, a_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
    dap_ledger_hardfork_balances_t *l_exist = NULL;
    DL_SEARCH(*a_out_list, l_exist, &l_new_balance, s_compare_balances);
    if (!l_exist) {
        l_exist = DAP_DUP(&l_new_balance);
        if (!l_exist) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return -1;
        }
        DL_APPEND(*a_out_list, l_exist);
    } else if (SUM_256_256(l_exist->value, a_value, &l_exist->value)) {
        log_it(L_ERROR, "Integer overflow of hardfork aggregated data for addr %s and token %s with value %s",
                                    dap_chain_addr_to_str_static(a_addr), a_ticker, dap_uint256_to_char(a_value, NULL));
        return -2;
    }
    return 0;
}

static int s_aggregate_out_cond(dap_ledger_hardfork_condouts_t **a_ret_list, dap_chain_tx_out_cond_t *a_out_cond, dap_sign_t *a_sign, dap_hash_fast_t *a_tx_hash)
{
    dap_ledger_hardfork_condouts_t *l_new_condout = DAP_NEW_Z(dap_ledger_hardfork_condouts_t);
    if (!l_new_condout) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -1;
    }
    *l_new_condout = (dap_ledger_hardfork_condouts_t) { .hash = *a_tx_hash, .cond = a_out_cond, .sign = a_sign };
    DL_APPEND(*a_ret_list, l_new_condout);
    return 0;
}

dap_ledger_hardfork_balances_t *dap_ledger_states_aggregate(dap_ledger_t *a_ledger, dap_ledger_hardfork_condouts_t **l_cond_outs_list)
{
    dap_ledger_hardfork_balances_t *ret = NULL;
    dap_ledger_hardfork_condouts_t *l_cond_ret = NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    for (dap_ledger_tx_item_t *it = l_ledger_pvt->ledger_items; it; it = it->hh.next) {
        if (it->cache_data.n_outs == it->cache_data.n_outs_used || it->cache_data.ts_spent)
            continue;
        uint8_t *l_tx_item = NULL;
        size_t l_size;
        int i, j = 0;
        TX_ITEM_ITER_TX_TYPE(l_tx_item, TX_ITEM_TYPE_OUT_ALL, l_size, i, it->tx) {
            if (!dap_hash_fast_is_blank(&it->cache_data.tx_hash_spent_fast[j++]))
                continue;
            uint8_t l_tx_item_type = *l_tx_item;
            switch(l_tx_item_type) {
            case TX_ITEM_TYPE_OUT: {
                dap_chain_tx_out_t *l_out = (dap_chain_tx_out_t *)l_tx_item;
                s_aggregate_out(&ret, it->cache_data.token_ticker, &l_out->addr, l_out->header.value);
                break;
            }
            case TX_ITEM_TYPE_OUT_OLD: {
                dap_chain_tx_out_old_t *l_out = (dap_chain_tx_out_old_t *)l_tx_item;
                s_aggregate_out(&ret, it->cache_data.token_ticker, &l_out->addr, GET_256_FROM_64(l_out->header.value));
                break;
            }
            case TX_ITEM_TYPE_OUT_EXT: {
                dap_chain_tx_out_ext_t *l_out = (dap_chain_tx_out_ext_t *)l_tx_item;
                s_aggregate_out(&ret, l_out->token, &l_out->addr, l_out->header.value);
                break;
            }
            case TX_ITEM_TYPE_OUT_COND: {
                dap_chain_tx_out_cond_t *l_out = (dap_chain_tx_out_cond_t *)l_tx_item;
                if (l_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)
                    continue;
                dap_hash_fast_t l_first_tx_hash = dap_ledger_get_first_chain_tx_hash(a_ledger, l_out->header.subtype, &it->tx_hash_fast);
                dap_chain_datum_tx_t *l_tx = dap_hash_fast_compare(&l_first_tx_hash, &it->tx_hash_fast) ? it->tx
                                                                                                        : dap_ledger_tx_find_by_hash(a_ledger, &l_first_tx_hash);
                if (!l_tx) {
                    log_it(L_ERROR, "Can't find header TX for conditional TX %s", dap_hash_fast_to_str_static(&it->tx_hash_fast));
                    continue;
                }
                dap_sign_t *l_tx_sign = dap_chain_datum_tx_get_sign(l_tx, 0);
                if (!l_tx_sign) {
                    log_it(L_ERROR, "Can't find sign for conditional TX %s", dap_hash_fast_to_str_static(&l_first_tx_hash));
                    continue;
                }
                s_aggregate_out_cond(&l_cond_ret, l_out, l_tx_sign, &it->tx_hash_fast);
            }
            default:
                log_it(L_ERROR, "Unexpected item type %hhu", l_tx_item_type);
                break;
            }
        }
    }
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    return ret;
}