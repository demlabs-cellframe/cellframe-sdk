 
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
#include "dap_chain_wallet.h"
#include "dap_chain_datum_tx_voting.h"

#define LOG_TAG "dap_ledger_tx"

typedef struct dap_ledger_verificator {
    int subtype;    // hash table key
    dap_ledger_cond_in_verify_callback_t callback_in_verify;
    dap_ledger_cond_out_verify_callback_t callback_out_verify;
    dap_ledger_cond_in_add_callback_t callback_in_add;
    dap_ledger_cond_out_add_callback_t callback_out_add;
    dap_ledger_cond_in_delete_callback_t callback_in_delete;
    dap_ledger_cond_out_delete_callback_t callback_out_delete;
    UT_hash_handle hh;
} dap_ledger_verificator_t;

typedef struct dap_chain_ledger_votings_callbacks {
    dap_ledger_voting_callback_t voting_callback;
    dap_ledger_vote_callback_t vote_callback;
    dap_ledger_voting_delete_callback_t voting_delete_callback;
    dap_ledger_voting_expire_callback_t voting_expire_callback;
} dap_chain_ledger_votings_callbacks_t;

static dap_ledger_verificator_t *s_verificators;
static pthread_rwlock_t s_verificators_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static dap_chain_ledger_votings_callbacks_t s_voting_callbacks;
static dap_ledger_tax_callback_t s_tax_callback = NULL;

typedef struct dap_ledger_tokenizer {
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t sum;
    struct dap_ledger_tokenizer *next;
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

typedef struct dap_ledger_cache_gdb_record {
    uint64_t cache_size, datum_size;
    uint8_t data[];
} DAP_ALIGN_PACKED dap_ledger_cache_gdb_record_t;

static bool s_ledger_tx_hash_is_used_out_item(dap_ledger_tx_item_t *a_item, uint32_t a_idx_out, dap_hash_fast_t *a_out_spender_hash);
static dap_ledger_stake_lock_item_t *s_emissions_for_stake_lock_item_find(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_token_emission_hash);
void dap_ledger_colour_clear_callback(void *a_list_data);
static dap_chain_datum_tx_t *s_tx_find_by_hash(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_tx_hash, dap_ledger_tx_item_t **a_item_out, bool a_unspent_only);
static struct json_object *s_wallet_info_json_collect(dap_ledger_t *a_ledger, dap_ledger_wallet_balance_t* a_bal);

static void s_ledger_stake_lock_cache_update(dap_ledger_t *a_ledger, dap_ledger_stake_lock_item_t *a_stake_lock_item);

static int s_sort_ledger_tx_item(dap_ledger_tx_item_t *a, dap_ledger_tx_item_t *b)
{
    return a->cache_data.ts_created < b->cache_data.ts_created ? -1
           : a->cache_data.ts_created > b->cache_data.ts_created ?
           1 : 0;
}

static int s_compare_locked_outs(dap_ledger_locked_out_t *a_out1, dap_ledger_locked_out_t *a_out2)
{
    return a_out1->unlock_time < a_out2->unlock_time ? -1
           : a_out1->unlock_time > a_out2->unlock_time ?
           1 : 0;
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
        dap_ledger_cache_gdb_record_t *l_current_record = (dap_ledger_cache_gdb_record_t *)a_values[i].value;
        if (a_values[i].value_len != l_current_record->cache_size + l_current_record->datum_size + sizeof(dap_ledger_cache_gdb_record_t)) {
            log_it(L_ERROR, "ledger_cache_gdb_record %zu size mismatch, %zu != %zu",
                            i, a_values[i].value_len, l_current_record->cache_size + l_current_record->datum_size + sizeof(dap_ledger_cache_gdb_record_t));
            continue;
        }
        dap_ledger_tx_item_t *l_tx_item = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_ledger_tx_item_t,
            sizeof(dap_ledger_tx_item_t) - sizeof(l_tx_item->cache_data) + l_current_record->cache_size, false);
        l_tx_item->tx = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_datum_tx_t, l_current_record->datum_size, false, l_tx_item);
        dap_chain_hash_fast_from_str(a_values[i].key, &l_tx_item->tx_hash_fast);
        memcpy(&l_tx_item->cache_data, l_current_record->data, l_current_record->cache_size);
        memcpy(l_tx_item->tx, l_current_record->data + l_current_record->cache_size, l_current_record->datum_size);
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

dap_ledger_tokenizer_t *s_tokenizer_find(dap_ledger_tokenizer_t *a_list, const char *a_ticker)
{
    for (dap_ledger_tokenizer_t *it = a_list; it; it = it->next)
        if (!dap_strcmp(it->token_ticker, a_ticker))
            return it;
    return NULL;
}

size_t s_tokenizer_count(dap_ledger_tokenizer_t *a_list)
{
    size_t ret = 0;
    for (dap_ledger_tokenizer_t *it = a_list; it; it = it->next)
        ret++;
    return ret;
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
                            dap_ledger_tokenizer_t **a_values_from_cur_tx,
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

    if (a_ledger->is_hardfork_state)
        return DAP_LEDGER_CHECK_OK;

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
    if (!a_from_threshold && dap_chain_datum_tx_verify_sign(a_tx, 0))
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
    bool l_tax_check = false;
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
                uint256_t l_stake_lock_ems_value;
                byte_t *l_tx_out = NULL;
                for (int l_item_idx = 0; ; l_item_idx++) {
                    if (!(l_tx_out = dap_chain_datum_tx_item_get(a_tx, &l_item_idx, NULL, TX_ITEM_TYPE_OUT_ALL, NULL)))
                        break;
                    if (*l_tx_out == TX_ITEM_TYPE_OUT_EXT) {
                        dap_chain_tx_out_ext_t *l_tx_out_ext = (dap_chain_tx_out_ext_t *)l_tx_out;
                        if (!strcmp(l_tx_out_ext->token, l_token)) {
                            l_stake_lock_ems_value = l_tx_out_ext->header.value;
                            break;
                        }
                    } else if (*l_tx_out == TX_ITEM_TYPE_OUT_STD) {
                        dap_chain_tx_out_std_t *l_tx_out_std = (dap_chain_tx_out_std_t *)l_tx_out;
                        if (l_tx_out_std->ts_unlock) {
                            debug_if(g_debug_ledger, L_WARNING, "Time lock is forbidden for stake lock txs");
                            l_err_num = DAP_LEDGER_TX_CHECK_TIMELOCK_ILLEGAL;
                            break;
                        }
                        if (!strcmp(l_tx_out_std->token, l_token)) {
                            l_stake_lock_ems_value = l_tx_out_std->value;
                            break;
                        }
                    } else if (*l_tx_out == TX_ITEM_TYPE_OUT) {
                        dap_chain_tx_out_t *l_tx_out_nontickered = (dap_chain_tx_out_t *)l_tx_out;
                        if (!l_girdled_ems) {
                            l_stake_lock_ems_value = l_tx_out_nontickered->header.value;
                            break;
                        }
                    }
                }
                if (l_err_num)
                    break;
                if (!l_tx_out) {
                    debug_if(g_debug_ledger, L_WARNING, l_girdled_ems ? "No OUT_EXT for girdled IN_EMS [%s]"
                                                                      : "Can't find OUT nor OUT_EXT item for base TX with IN_EMS [%s]", l_tx_in_ems->header.ticker);
                    l_err_num = l_girdled_ems ? DAP_LEDGER_TX_CHECK_NO_OUT_EXT_FOR_GIRDLED_IN_EMS : DAP_LEDGER_TX_CHECK_NO_OUT_ITEMS_FOR_BASE_TX;
                    break;
                }

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
                if (l_stake_lock_emission)
                    l_bound_item->stake_lock_item = l_stake_lock_emission;
                l_value = l_stake_lock_ems_value;
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
                dap_sign_t *l_tx_first_sign = dap_chain_datum_tx_item_sig_get_sign(l_tx_sig);
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
                debug_if(g_debug_ledger, L_INFO, "'Out' item %u of previous tx %s already spent by %s", l_tx_prev_out_idx, l_tx_prev_hash_str, l_hash);
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
                dap_sign_t *l_tx_first_sign = dap_chain_datum_tx_item_sig_get_sign(l_tx_sig);
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
                case TX_ITEM_TYPE_OUT_STD:
                    if (((dap_chain_tx_out_std_t *)l_tx_prev_out)->ts_unlock > PVT(a_ledger)->blockchain_time) {
                        l_err_num = DAP_LEDGER_TX_CHECK_PREV_OUT_ITEM_LOCKED;
                        break;
                    }
                    l_addr_from = &((dap_chain_tx_out_std_t *)l_tx_prev_out)->addr;
                    l_value = ((dap_chain_tx_out_std_t *)l_tx_prev_out)->value;
                    l_token = ((dap_chain_tx_out_std_t *)l_tx_prev_out)->token;
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
                dap_sign_t *l_sign = dap_chain_datum_tx_item_sig_get_sign((dap_chain_tx_sig_t *)l_tx_sig);
                dap_chain_tx_sig_t *l_owner_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(l_owner_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
                dap_sign_t *l_owner_sign = dap_chain_datum_tx_item_sig_get_sign((dap_chain_tx_sig_t *)l_owner_tx_sig);

                bool l_owner = false;
                l_owner = dap_sign_compare_pkeys(l_owner_sign, l_sign);

                // 5b. Call verificator for conditional output
                dap_ledger_verificator_t *l_verificator = NULL;
                int l_sub_tmp = l_tx_prev_out_cond->header.subtype;

                pthread_rwlock_rdlock(&s_verificators_rwlock);
                HASH_FIND_INT(s_verificators, &l_sub_tmp, l_verificator);
                pthread_rwlock_unlock(&s_verificators_rwlock);
                if (!l_verificator || !l_verificator->callback_in_verify) {
                    debug_if(g_debug_ledger, L_ERROR, "No verificator set for condition subtype %d", l_sub_tmp);
                    l_err_num = DAP_LEDGER_TX_CHECK_NO_VERIFICATOR_SET;
                    break;
                }

                int l_verificator_error = l_verificator->callback_in_verify(a_ledger, a_tx, a_tx_hash, l_tx_prev_out_cond, l_owner);
                if (l_verificator_error != DAP_LEDGER_CHECK_OK) { // TODO add string representation for verificator return codes
                    debug_if(g_debug_ledger, L_WARNING, "Verificator check error %d for conditional input %s",
                                                                    l_verificator_error, dap_chain_tx_out_cond_subtype_to_str(l_sub_tmp));

                    // Retranslate NO_SIGNS code to upper level
                    l_err_num = l_verificator_error == DAP_CHAIN_CS_VERIFY_CODE_NOT_ENOUGH_SIGNS ? l_verificator_error : DAP_LEDGER_TX_CHECK_VERIFICATOR_CHECK_FAILURE;
                    break;
                }
                l_bound_item->cond = l_tx_prev_out_cond;
                l_value = l_tx_prev_out_cond->header.value;
                if (l_tx_prev_out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE) {
                    l_tax_check = true;
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
        l_value_cur = s_tokenizer_find(l_values_from_prev_tx, l_token);
        if (!l_value_cur) {
            l_value_cur = DAP_NEW_Z(dap_ledger_tokenizer_t);
            if ( !l_value_cur ) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                l_err_num = DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
                break;
            }
            dap_strncpy(l_value_cur->token_ticker, l_token, DAP_CHAIN_TICKER_SIZE_MAX);
            LL_APPEND(l_values_from_prev_tx, l_value_cur);
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
        LL_FOREACH_SAFE(l_values_from_prev_tx, l_value_cur, l_tmp)
            DAP_DELETE(l_value_cur);
        return l_err_num;
    }

    // 6. Compare sum of values in 'out' items
    if ( !l_main_ticker )
        switch ( s_tokenizer_count(l_values_from_prev_tx) ) {
        case 1:
            l_main_ticker = l_value_cur->token_ticker;
            break;
        case 2:
            l_value_cur = s_tokenizer_find(l_values_from_prev_tx, a_ledger->net->pub.native_ticker);
            if (l_value_cur) {
                l_value_cur = l_value_cur->next ? l_value_cur->next : l_values_from_prev_tx;
                l_main_ticker = l_value_cur->token_ticker;
            }
            break;
        default:
            dap_list_free_full(l_list_bound_items, NULL);
            LL_FOREACH_SAFE(l_values_from_prev_tx, l_value_cur, l_tmp)
                DAP_DELETE(l_value_cur);
            return DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER;
        }

    dap_chain_addr_t l_sovereign_addr; uint256_t l_sovereign_tax;
    l_tax_check = l_tax_check && s_tax_callback
        ? s_tax_callback(a_ledger->net->pub.id, &l_tx_first_sign_pkey_hash, &l_sovereign_addr, &l_sovereign_tax)
        : false;
    // find 'out' items
    bool l_cross_network = false;
    uint256_t l_value = {}, l_fee_sum = {}, l_tax_sum = {};
    bool l_fee_check = !IS_ZERO_256(a_ledger->net->pub.fee_value) && !dap_chain_addr_is_blank(&a_ledger->net->pub.fee_addr);
    int l_item_idx = 0;
    byte_t *it; size_t l_size;
    TX_ITEM_ITER_TX(it, l_size, a_tx) {
        dap_chain_addr_t l_tx_out_to = { };
        switch ( *it ) {
        case TX_ITEM_TYPE_OUT_OLD: {
            dap_chain_tx_out_old_t *l_tx_out = (dap_chain_tx_out_old_t*)it;
            if (!( l_token = l_main_ticker )) {
                l_err_num = DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER;
                break;
            }
            l_value = dap_chain_uint256_from(l_tx_out->header.value);
            l_tx_out_to = l_tx_out->addr;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        case TX_ITEM_TYPE_OUT: { // 256
            dap_chain_tx_out_t *l_tx_out = (dap_chain_tx_out_t *)it;
            if (!( l_token = l_main_ticker )) {
                l_err_num = DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER;
                break;
            }
            l_value = l_tx_out->header.value;
            l_tx_out_to = l_tx_out->addr;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        case TX_ITEM_TYPE_OUT_EXT: { // 256
            dap_chain_tx_out_ext_t *l_tx_out = (dap_chain_tx_out_ext_t *)it;
            l_value = l_tx_out->header.value;
            l_token = l_tx_out->token;
            l_tx_out_to = l_tx_out->addr;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        case TX_ITEM_TYPE_OUT_STD: {
            dap_chain_tx_out_std_t *l_tx_out = (dap_chain_tx_out_std_t *)it;
            if (l_tx_out->ts_unlock && !dap_chain_policy_activated(DAP_CHAIN_POLICY_OUT_STD_TIMELOCK_USE, a_ledger->net->pub.id.uint64)) {
                l_err_num = DAP_LEDGER_TX_CHECK_TIMELOCK_ILLEGAL;
                break;
            }
            l_value = l_tx_out->value;
            l_token = l_tx_out->token;
            l_tx_out_to = l_tx_out->addr;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        case TX_ITEM_TYPE_OUT_COND: {
            dap_chain_tx_out_cond_t *l_tx_out = (dap_chain_tx_out_cond_t *)it;
            if (!( l_token = l_tx_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE ? a_ledger->net->pub.native_ticker : l_main_ticker )) {
                l_err_num = DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER;
                break;
            }
            l_value = l_tx_out->header.value;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
            if (l_tax_check && l_tx_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE &&
                    SUBTRACT_256_256(l_taxed_value, l_value, &l_taxed_value)) {
                log_it(L_WARNING, "Fee is greater than sum of inputs");
                l_err_num = DAP_LEDGER_CHECK_INTEGER_OVERFLOW;
                break;
            }
            dap_ledger_verificator_t *l_verificator = NULL;
            int l_subtype = l_tx_out->header.subtype;
            pthread_rwlock_rdlock(&s_verificators_rwlock);
            HASH_FIND_INT(s_verificators, &l_subtype, l_verificator);
            pthread_rwlock_unlock(&s_verificators_rwlock);
            if (l_verificator && l_verificator->callback_out_verify) {
                int l_verificator_error = l_verificator->callback_out_verify(a_ledger, a_tx, a_tx_hash, l_tx_out);
                if (l_verificator_error != DAP_LEDGER_CHECK_OK) {
                    debug_if(g_debug_ledger, L_WARNING, "Verificator check error %d for conditional output %s",
                                                                l_verificator_error, dap_chain_tx_out_cond_subtype_to_str(l_subtype));
                    l_err_num = DAP_LEDGER_TX_CHECK_VERIFICATOR_CHECK_FAILURE;
                    break;
                }
            }
        } break;
        default:
            continue;
        }
        if (!dap_chain_addr_is_blank(&l_tx_out_to)) {
            if (l_tx_out_to.net_id.uint64 != a_ledger->net->pub.id.uint64) {
                if (!l_cross_network) {
                    l_cross_network = true;
                } else {
                    log_it(L_WARNING,
                           "The transaction was rejected because it contains multiple outputs to other network.");
                    l_err_num = DAP_LEDGER_TX_CHECK_MULTIPLE_OUTS_TO_OTHER_NET;
                    break;
                }
            }
        }

        if (l_err_num)
            break;
        l_value_cur = s_tokenizer_find(l_values_from_cur_tx, l_token);
        if (!l_value_cur) {
            l_value_cur = DAP_NEW_Z(dap_ledger_tokenizer_t);
            if ( !l_value_cur ) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                l_err_num = DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
                break;
            }
            dap_strncpy(l_value_cur->token_ticker, l_token, sizeof(l_value_cur->token_ticker));
            LL_APPEND(l_values_from_cur_tx, l_value_cur);
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
    if ( !l_err_num && !dap_ledger_datum_is_enforced(a_ledger, a_tx_hash, true) ) {
        if ( s_tokenizer_count(l_values_from_prev_tx) != s_tokenizer_count(l_values_from_cur_tx) ) {
            log_it(L_ERROR, "Token tickers IN and OUT mismatch: %zu != %zu",
                            s_tokenizer_count(l_values_from_prev_tx), s_tokenizer_count(l_values_from_cur_tx));
            l_err_num = DAP_LEDGER_TX_CHECK_SUM_INS_NOT_EQUAL_SUM_OUTS;
        } else {
            LL_FOREACH(l_values_from_prev_tx, l_value_cur) {
                l_res = s_tokenizer_find(l_values_from_cur_tx, l_value_cur->token_ticker);
                if ( !l_res || !EQUAL_256(l_res->sum, l_value_cur->sum) ) {
                    if (g_debug_ledger) {
                        char *l_balance = dap_chain_balance_coins_print(l_res ? l_res->sum : uint256_0), 
                             *l_balance_cur = dap_chain_balance_coins_print(l_value_cur->sum);
                        log_it(L_ERROR, "Sum of values of out items from current tx (%s) is not equal outs from previous txs (%s) for token %s",
                                l_balance, l_balance_cur, l_value_cur->token_ticker);
                        DAP_DEL_MULTY(l_balance, l_balance_cur);
                    }
                    l_err_num = DAP_LEDGER_TX_CHECK_SUM_INS_NOT_EQUAL_SUM_OUTS;
                    break;
                }
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
                if ((l_err_num = s_voting_callbacks.voting_callback(a_ledger, a_tx, a_tx_hash, false))) {
                    debug_if(g_debug_ledger, L_WARNING, "Verificator check error %d for voting", l_err_num);
                    l_err_num = DAP_LEDGER_TX_CHECK_VERIFICATOR_CHECK_FAILURE;
                }
            } else {
                debug_if(g_debug_ledger, L_WARNING, "Verificator check error for voting item");
                l_err_num = DAP_LEDGER_TX_CHECK_NO_VERIFICATOR_SET;
            }
            if (a_action) 
               *a_action = DAP_CHAIN_TX_TAG_ACTION_VOTING;
        } else if ( dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_VOTE, NULL) ) {
           if (s_voting_callbacks.voting_callback) {
               if ((l_err_num = s_voting_callbacks.vote_callback(a_ledger, a_tx, a_tx_hash, NULL, false))) {
                   debug_if(g_debug_ledger, L_WARNING, "Verificator check error %d for vote", l_err_num);
                   l_err_num = DAP_LEDGER_TX_CHECK_VERIFICATOR_CHECK_FAILURE;
               }
           } else {
               debug_if(g_debug_ledger, L_WARNING, "Verificator check error for vote item");
               l_err_num = DAP_LEDGER_TX_CHECK_NO_VERIFICATOR_SET;
           }
           if (a_action) 
               *a_action = DAP_CHAIN_TX_TAG_ACTION_VOTE;
        }
    }

    if (a_main_ticker && !l_err_num && (a_main_ticker != l_main_ticker))
        dap_strncpy(a_main_ticker, l_main_ticker, DAP_CHAIN_TICKER_SIZE_MAX);

    LL_FOREACH_SAFE(l_values_from_prev_tx, l_value_cur, l_tmp)
        DAP_DELETE(l_value_cur);

    if (!a_values_from_cur_tx || l_err_num) {
        LL_FOREACH_SAFE(l_values_from_cur_tx, l_value_cur, l_tmp)
            DAP_DELETE(l_value_cur);
    } else
        *a_values_from_cur_tx = l_values_from_cur_tx;

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
    int l_ret_check = s_tx_cache_check(a_ledger, a_tx, a_datum_hash, false, NULL, NULL, NULL, NULL, NULL, NULL, false);
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
    char *pos = strrchr(a_bal->key, ' ');
    if (pos) {
        size_t l_addr_len = pos - a_bal->key;
        char l_addr_str[l_addr_len + 1];
        dap_strncpy(l_addr_str, a_bal->key, l_addr_len + 1);
        dap_chain_addr_t *l_addr = dap_chain_addr_from_str(l_addr_str);
        const char *l_wallet_name = dap_chain_wallet_addr_cache_get_name(l_addr);
        DAP_DELETE(l_addr);
        if (l_wallet_name) {
            struct json_object *l_json = json_object_new_object();
            json_object_object_add(l_json, "class", json_object_new_string("WalletInfo"));
            struct json_object *l_jobj_wallet = json_object_new_object();
            json_object_object_add(l_jobj_wallet, l_wallet_name, dap_chain_wallet_info_to_json(l_wallet_name,
                                                                                               dap_chain_wallet_get_path(g_config)));
            json_object_object_add(l_json, "wallet", l_jobj_wallet);
            return l_json;
        }
    }
    return NULL;
}

/**
 * @brief s_balance_cache_update
 * @param a_ledger
 * @param a_balance
 * @return
 */
static int s_balance_cache_update(dap_ledger_t *a_ledger, dap_ledger_wallet_balance_t *a_balance)
{
    if ( is_ledger_cached(PVT(a_ledger)) ) {
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
        if (l_json) {
            dap_notify_server_send(json_object_get_string(l_json));
            json_object_put(l_json);
        }
    }
    return 0;
}

struct tracker_mover_item {
    dap_hash_fast_t pkey_hash;
    uint256_t coloured_value;
    uint256_t cur_value;
    struct tracker_mover_item *prev, *next;
};

struct tracker_mover {
    dap_hash_fast_t voting_hash;
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    struct tracker_mover_item *items;
};

int s_compare_tracker_items(struct tracker_mover_item *a_item1, struct tracker_mover_item *a_item2)
{
    return memcmp(&a_item1->pkey_hash, &a_item1->pkey_hash, sizeof(dap_hash_fast_t));
}

int s_compare_trackers(dap_list_t *a_tracker1, dap_list_t *a_tracker2)
{
    struct tracker_mover *l_tracker1 = a_tracker1->data, *l_tracker2 = a_tracker2->data;
    return memcmp(&l_tracker1->voting_hash, &l_tracker2->voting_hash, sizeof(dap_hash_fast_t));
}

dap_list_t *s_trackers_aggregate(dap_ledger_t *a_ledger, dap_list_t *a_trackers, const char *a_ticker,
                                 dap_hash_fast_t *a_voting_hash, dap_hash_fast_t *a_pkey_hash,
                                 dap_list_t **a_added, dap_time_t a_ts_creation_time)
{
    dap_return_val_if_fail(s_voting_callbacks.voting_expire_callback, a_trackers);
    dap_list_t *it, *tmp;
    DL_FOREACH_SAFE(*a_added, it, tmp) {
        dap_ledger_tracker_t *l_new_tracker = it->data;
        dap_time_t l_exp_time = s_voting_callbacks.voting_expire_callback(a_ledger, &l_new_tracker->voting_hash);
        if (a_ts_creation_time > l_exp_time) {
            DL_DELETE(*a_added, it);
            dap_ledger_colour_clear_callback(it->data);
            DAP_DELETE(it);
            continue;       // Remove expired colour
        }
        dap_list_t *l_exists = dap_list_find(a_trackers, &l_new_tracker->voting_hash, s_compare_trackers);
        struct tracker_mover *l_exists_tracker = NULL;
        if (!l_exists) {
            l_exists_tracker = DAP_NEW_Z_RET_VAL_IF_FAIL(struct tracker_mover, a_trackers);
            l_exists_tracker->voting_hash = l_new_tracker->voting_hash;
            dap_strncpy(l_exists_tracker->ticker, a_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
            a_trackers = dap_list_append(a_trackers, l_exists_tracker);
        } else
            l_exists_tracker = l_exists->data;
        dap_ledger_tracker_item_t *l_item;
        DL_FOREACH(l_new_tracker->items, l_item) {
            if (a_voting_hash && dap_hash_fast_compare(a_voting_hash, &l_exists_tracker->voting_hash) &&
                    dap_hash_fast_compare(a_pkey_hash, &l_item->pkey_hash))
                continue;
            struct tracker_mover_item *l_exists_item, l_sought = { .pkey_hash = l_item->pkey_hash };
            DL_SEARCH(l_exists_tracker->items, l_exists_item, &l_sought, s_compare_tracker_items);
            if (!l_exists_item) {
                l_exists_item = DAP_NEW_Z_RET_VAL_IF_FAIL(struct tracker_mover_item, a_trackers);
                l_exists_item->pkey_hash = l_item->pkey_hash;
                DL_APPEND(l_exists_tracker->items, l_exists_item);
            }
            if (SUM_256_256(l_exists_item->coloured_value, l_item->coloured_value, &l_exists_item->coloured_value)) {
                log_it(L_ERROR, "Tracking value overflow, can't track voting %s anymore", dap_hash_fast_to_str_static(&l_new_tracker->voting_hash));
                return a_trackers;
            }
            l_exists_item->cur_value = l_exists_item->coloured_value;
        }
    }
    return a_trackers;
}

void s_trackers_clear(void *a_list_elm)
{
    struct tracker_mover *l_free = a_list_elm;
    struct tracker_mover_item *it, *tmp;
    DL_FOREACH_SAFE(l_free->items, it, tmp)
        DAP_DELETE(it); // No need for DL_DELETE cause clear the full list
    DAP_DELETE(a_list_elm);
}

int s_balance_update_for_addr(dap_ledger_t *a_ledger, dap_chain_addr_t *a_addr, const char *a_token_ticker, uint256_t a_value)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    const char *l_addr_str = dap_chain_addr_to_str_static(a_addr);
    dap_ledger_wallet_balance_t *wallet_balance = NULL;
    char *l_wallet_balance_key = dap_strjoin(" ", l_addr_str, a_token_ticker, (char*)NULL);
    debug_if(g_debug_ledger, L_DEBUG, "GOT %s to addr: %s", dap_uint256_to_char(a_value, NULL), l_wallet_balance_key);
    pthread_rwlock_rdlock(&l_ledger_pvt->balance_accounts_rwlock);
    HASH_FIND_STR(l_ledger_pvt->balance_accounts, l_wallet_balance_key, wallet_balance);
    pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
    if (wallet_balance) {
        SUM_256_256(wallet_balance->balance, a_value, &wallet_balance->balance);
        DAP_DELETE (l_wallet_balance_key);
        // Update the cache
        s_balance_cache_update(a_ledger, wallet_balance);
    } else {
        wallet_balance = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_ledger_wallet_balance_t, -1);
        wallet_balance->key = l_wallet_balance_key;
        strcpy(wallet_balance->token_ticker, a_token_ticker);
        SUM_256_256(wallet_balance->balance, a_value, &wallet_balance->balance);
        debug_if(g_debug_ledger, L_DEBUG, "Create new balance item: %s %s", l_addr_str, a_token_ticker);
        pthread_rwlock_wrlock(&l_ledger_pvt->balance_accounts_rwlock);
        HASH_ADD_KEYPTR(hh, PVT(a_ledger)->balance_accounts, wallet_balance->key,
                        strlen(l_wallet_balance_key), wallet_balance);
        pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
        // Add it to cache
        s_balance_cache_update(a_ledger, wallet_balance);
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
    dap_list_t *l_trackers_mover = NULL;
    bool l_from_threshold = a_from_threshold;
    dap_hash_fast_t l_tx_hash = *a_tx_hash;
    byte_t *l_item = NULL;
    size_t l_tx_item_size = 0;

    if (a_ledger->is_hardfork_state) {
        struct tracker_mover *l_hardfork_tracker = NULL;
        TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx) {
            if (*l_item == TX_ITEM_TYPE_OUT_STD || *l_item == TX_ITEM_TYPE_OUT_COND) {
                l_list_tx_out = dap_list_append(l_list_tx_out, l_item);
                continue;
            }
            if (*l_item != TX_ITEM_TYPE_TSD)
                continue;
            dap_tsd_t *l_tsd = (dap_tsd_t *)((dap_chain_tx_tsd_t *)l_item)->tsd;
            switch (l_tsd->type) {
            case DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_TX_HASH: {
                if (l_tsd->size != sizeof(dap_hash_fast_t)) {
                    log_it(L_WARNING, "Incorrect size of TSD tracker section %u (need %zu)", l_tsd->size, sizeof(dap_hash_fast_t));
                    break;
                }
                l_tx_hash = *(dap_hash_fast_t *)l_tsd->data;
            } break;
            case DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_TICKER: {
                if (!l_tsd->size || l_tsd->size > DAP_CHAIN_TICKER_SIZE_MAX) {
                    log_it(L_WARNING, "Illegal harfork datum tx TSD TICKER size %u", l_tsd->size);
                    break;
                }
                dap_strncpy(l_main_token_ticker, (char *)l_tsd->data, DAP_CHAIN_TICKER_SIZE_MAX);
            } break;
            case DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_VOTING_HASH: {
                if (l_tsd->size != sizeof(dap_hash_fast_t)) {
                    log_it(L_WARNING, "Illegal harfork datum tx TSD VOTING_HASH size %u", l_tsd->size);
                    break;
                }
                l_hardfork_tracker = DAP_NEW_Z(struct tracker_mover);
                if (!l_hardfork_tracker) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    break;
                }
                l_hardfork_tracker->voting_hash = *(dap_hash_fast_t *)l_tsd->data;
                l_trackers_mover = dap_list_append(l_trackers_mover, l_hardfork_tracker);
            } break;
            case DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_TRACKER: {
                if (l_tsd->size != sizeof(dap_ledger_hardfork_tracker_t)) {
                    log_it(L_WARNING, "Illegal harfork datum tx TSD TRACKER size %u", l_tsd->size);
                    break;
                }
                if (!l_hardfork_tracker) {
                    log_it(L_WARNING, "No voting hash defined for tracking item");
                    break;
                }
                dap_ledger_hardfork_tracker_t *l_tsd_item = (dap_ledger_hardfork_tracker_t *)l_tsd->data;
                struct tracker_mover_item *l_tracker_item = DAP_NEW_Z(struct tracker_mover_item);
                if (!l_tracker_item) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    break;
                }
                l_tracker_item->pkey_hash = l_tsd_item->pkey_hash;
                l_tracker_item->coloured_value = l_tsd_item->coloured_value;
                DL_APPEND(l_hardfork_tracker->items, l_tracker_item);
            } break;
            default:
                log_it(L_WARNING, "Illegal harfork datum tx TSD item type 0x%X", l_tsd->type);
                break;
            }
        }
    }

    char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(a_tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));

    int l_ret_check;
    dap_chain_srv_uid_t l_tag =  { .uint64 = 0 };
    dap_chain_tx_tag_action_type_t l_action = DAP_CHAIN_TX_TAG_ACTION_UNKNOWN;
    dap_ledger_tokenizer_t *l_values_from_cur_tx = NULL;
    if( (l_ret_check = s_tx_cache_check(a_ledger, a_tx, &l_tx_hash, a_from_threshold,
                                        &l_list_bound_items, &l_list_tx_out,
                                        l_main_token_ticker, &l_values_from_cur_tx,
                                        &l_tag, &l_action, false))) {
        if ((l_ret_check == DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS ||
                l_ret_check == DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION) &&
                is_ledger_threshld(l_ledger_pvt) && !dap_chain_net_get_load_mode(a_ledger->net)) {
            if (!l_from_threshold)
                dap_ledger_pvt_threshold_txs_add(a_ledger, a_tx, &l_tx_hash);
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
    if ( is_ledger_cached(l_ledger_pvt) ) {
        l_cache_used_outs = DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(dap_store_obj_t) * (l_outs_used + 1));
        if ( !l_cache_used_outs ) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            l_ret = -1;
            goto FIN;
        }
        l_ledger_cache_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_TXS_STR);
    }

    int l_err_num = 0;
    dap_hash_fast_t l_vote_pkey_hash = { };
    dap_chain_tx_vote_t *l_vote_tx_item = NULL;
    if (s_voting_callbacks.voting_callback) {
        if (l_action == DAP_CHAIN_TX_TAG_ACTION_VOTING)
            l_err_num = s_voting_callbacks.voting_callback(a_ledger, a_tx, &l_tx_hash, true);
        else if (l_action == DAP_CHAIN_TX_TAG_ACTION_VOTE) {
            l_err_num = s_voting_callbacks.vote_callback(a_ledger, a_tx, &l_tx_hash, &l_vote_pkey_hash, true);
            l_vote_tx_item = (dap_chain_tx_vote_t *)dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_VOTE, NULL);
            assert(l_vote_tx_item);
        }
    }
    assert(!l_err_num);

    // Update balance: deducts
    const char *l_cur_token_ticker = NULL;
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
            l_bound_item->emission_item->tx_used_out = l_tx_hash;
            dap_ledger_pvt_emission_cache_update(a_ledger, l_bound_item->emission_item);
            l_outs_used--; // Do not calc this output with tx used items
            continue;

        case TX_ITEM_TYPE_IN_EMS_LOCK:
            if (l_bound_item->stake_lock_item) { // Legacy stake lock emission
                // Mark it as used with current tx hash
                l_bound_item->stake_lock_item->tx_used_out = l_tx_hash;
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
            l_item->spender_tx = l_tx_hash;
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
            if (l_verificator && l_verificator->callback_in_add)
                l_verificator->callback_in_add(a_ledger, a_tx, &l_tx_hash, l_bound_item->cond);
        } break;

        default:
            log_it(L_ERROR, "Unknown item type %d in ledger TX bound for IN part", l_type);
            break;
        }

        // Gather colour information from previous outputs
        dap_ledger_tx_item_t *l_prev_item_out = l_bound_item->prev_item;
        l_prev_item_out->out_metadata[l_bound_item->prev_out_idx].tx_spent_hash_fast = l_tx_hash;
        // Clear trackers info for immutable tx's
        if (l_prev_item_out->cache_data.flags & LEDGER_PVT_TX_META_FLAG_IMMUTABLE)
            dap_list_free_full(l_prev_item_out->out_metadata[l_bound_item->prev_out_idx].trackers, dap_ledger_colour_clear_callback);
        else
            l_trackers_mover = s_trackers_aggregate(a_ledger, l_trackers_mover, l_bound_item->in.token_ticker,
                                                    l_vote_tx_item ? &l_vote_tx_item->voting_hash : NULL, &l_vote_pkey_hash,
                                                    &l_prev_item_out->out_metadata[l_bound_item->prev_out_idx].trackers, a_tx->header.ts_created);
        // add a used output
        l_prev_item_out->cache_data.n_outs_used++;
        if ( is_ledger_cached(l_ledger_pvt) ) {
            // mirror it in the cache
            size_t l_cache_size = sizeof(l_prev_item_out->cache_data) + l_prev_item_out->cache_data.n_outs * sizeof(dap_chain_hash_fast_t);
            size_t l_tx_size = dap_chain_datum_tx_get_size(l_prev_item_out->tx);
            size_t l_tx_cache_sz = l_tx_size + l_cache_size + sizeof(dap_ledger_cache_gdb_record_t);
            dap_ledger_cache_gdb_record_t *l_tx_cache = DAP_NEW_Z_SIZE(dap_ledger_cache_gdb_record_t, l_tx_cache_sz);
            l_tx_cache->cache_size = l_cache_size;
            l_tx_cache->datum_size = l_tx_size;
            memcpy(l_tx_cache->data, &l_prev_item_out->cache_data, l_cache_size);
            memcpy(l_tx_cache->data + l_cache_size, l_prev_item_out->tx, l_tx_size);
            l_cache_used_outs[l_spent_idx] = (dap_store_obj_t) {
                    .key        = dap_chain_hash_fast_to_str_new(&l_prev_item_out->tx_hash_fast),
                    .value      = (byte_t*)l_tx_cache,
                    .value_len  = l_tx_cache_sz,
                    .group      = l_ledger_cache_group,
            };
            l_cache_used_outs[l_spent_idx].timestamp = dap_nanotime_now();
        }
        // mark previous transactions as used with the extra timestamp
        if (l_prev_item_out->cache_data.n_outs_used == l_prev_item_out->cache_data.n_outs)
            l_prev_item_out->cache_data.ts_spent = a_tx->header.ts_created;
    }

    uint32_t l_outs_count = dap_list_length(l_list_tx_out);
    dap_ledger_tx_item_t *l_tx_item = DAP_NEW_Z_SIZE(dap_ledger_tx_item_t, sizeof(dap_ledger_tx_item_t) + l_outs_count * sizeof(dap_ledger_tx_out_metadata_t));
    if ( !l_tx_item ) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        l_ret = -1;
        goto FIN;
    }
    l_tx_item->tx_hash_fast = l_tx_hash;
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    l_tx_item->tx = is_ledger_mapped(l_ledger_pvt) ? a_tx : DAP_DUP_SIZE(a_tx, l_tx_size);
    l_tx_item->cache_data.n_outs = l_outs_count;
    l_tx_item->cache_data.tag = l_tag;
    l_tx_item->cache_data.action = l_action;
    dap_strncpy(l_tx_item->cache_data.token_ticker, l_main_token_ticker, sizeof(l_tx_item->cache_data.token_ticker));

    //Update balance : raise
    bool l_cross_network = false, l_multichannel = false;
    uint32_t i = 0;
    for (dap_list_t *l_tx_out = l_list_tx_out; l_tx_out; l_tx_out = l_tx_out->next, i++) {
        assert(l_tx_out->data);
        dap_chain_tx_item_type_t l_type = *(uint8_t *)l_tx_out->data;

        dap_chain_addr_t *l_addr = NULL;
        uint256_t l_value = {};
        bool l_balance_update = true;
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
        case TX_ITEM_TYPE_OUT_STD: {
            dap_chain_tx_out_std_t *l_out_item_std = (dap_chain_tx_out_std_t *)l_tx_out->data;
            l_addr = &l_out_item_std->addr;
            l_value = l_out_item_std->value;
            l_cur_token_ticker = l_out_item_std->token;
            if (l_out_item_std->ts_unlock > l_ledger_pvt->blockchain_time) {
                dap_ledger_locked_out_t *l_new_locked_out = DAP_NEW_Z(dap_ledger_locked_out_t);
                if (!l_new_locked_out) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    goto FIN;
                }
                l_new_locked_out->tx_hash = l_tx_hash;
                l_new_locked_out->out_num = i;
                l_new_locked_out->unlock_time = l_out_item_std->ts_unlock;
                LL_INSERT_INORDER(l_ledger_pvt->locked_outs, l_new_locked_out, s_compare_locked_outs);
                l_balance_update = false;
            }
        } break;
        case TX_ITEM_TYPE_OUT_COND: {
            // Update service items if any
            dap_chain_tx_out_cond_t *l_cond = (dap_chain_tx_out_cond_t *)l_tx_out->data;
            dap_ledger_verificator_t *l_verificator = NULL;
            int l_tmp = l_cond->header.subtype;
            pthread_rwlock_rdlock(&s_verificators_rwlock);
            HASH_FIND_INT(s_verificators, &l_tmp, l_verificator);
            pthread_rwlock_unlock(&s_verificators_rwlock);
            if (l_verificator && l_verificator->callback_out_add)
                l_verificator->callback_out_add(a_ledger, a_tx, &l_tx_hash, l_cond);
            l_value = l_cond->header.value;
            l_cur_token_ticker = l_main_token_ticker;
            l_balance_update = false;
        } break;
        default:
            log_it(L_ERROR, "Unknown item type %d", l_type);
            goto FIN;
        }

        assert(l_addr);
        if (l_addr->net_id.uint64 != a_ledger->net->pub.id.uint64 &&
                !dap_chain_addr_is_blank(l_addr))
            l_cross_network = true;
        if (!l_multichannel && dap_strcmp(l_main_token_ticker, l_cur_token_ticker))
            l_multichannel = true;

        if (l_balance_update)
            s_balance_update_for_addr(a_ledger, l_addr, l_cur_token_ticker, l_value);

        // Moving colour to new outputs
        bool l_voting_found = false;
        for (dap_list_t *mv = l_trackers_mover; mv; mv = mv->next) {
            struct tracker_mover *l_mover = mv->data;
            assert(!dap_hash_fast_is_blank(&l_mover->voting_hash));
            bool l_vote_add = false;
            if (!l_voting_found && l_vote_tx_item && dap_hash_fast_compare(&l_mover->voting_hash, &l_vote_tx_item->voting_hash))
                l_voting_found = l_vote_add = true;
            uint256_t l_moving_sum = {};
            if (!a_ledger->is_hardfork_state) {
                if (dap_strcmp(l_cur_token_ticker, l_mover->ticker))
                    continue;
                dap_ledger_tokenizer_t *l_moving_sum_per_token = s_tokenizer_find(l_values_from_cur_tx, l_mover->ticker);
                assert(l_moving_sum_per_token);
                l_moving_sum = l_moving_sum_per_token->sum;
            } else
                l_moving_sum = l_value;
            dap_ledger_tracker_t *l_tracker = NULL;
            struct tracker_mover_item *it;
            uint256_t l_moved_value = {};
            DL_FOREACH(l_mover->items, it) {
                if (IS_ZERO_256(it->cur_value))
                    continue;
                if (!l_tracker) {
                    l_tracker = DAP_NEW_Z(dap_ledger_tracker_t);
                    if (!l_tracker) {
                        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                        goto FIN;
                    }
                    l_tracker->voting_hash = l_mover->voting_hash;
                }
                dap_ledger_tracker_item_t *l_tracker_item = DAP_NEW_Z(dap_ledger_tracker_item_t);
                if (!l_tracker_item) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    goto FIN;
                }
                l_tracker_item->pkey_hash = it->pkey_hash;
                DL_APPEND(l_tracker->items, l_tracker_item);
                uint256_t l_coloured_value;
                MULT_256_256(l_value, it->coloured_value, &l_coloured_value);
                DIV_256(l_coloured_value, l_moving_sum, &l_coloured_value);
                if (compare256(it->cur_value, l_coloured_value) > 0 &&
                        !IS_ZERO_256(l_coloured_value)) {
                    SUBTRACT_256_256(it->cur_value, l_coloured_value, &it->cur_value);
                    l_tracker_item->coloured_value = l_coloured_value;
                } else {
                    l_tracker_item->coloured_value = it->cur_value;
                    it->cur_value = uint256_0;
                }
                if (l_vote_add)
                    SUM_256_256(l_moved_value, l_tracker_item->coloured_value, &l_moved_value);
            }
            if (l_vote_add) {
                dap_ledger_tracker_item_t *l_tracker_item = DAP_NEW_Z(dap_ledger_tracker_item_t);
                if (!l_tracker_item) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    goto FIN;
                }
                l_tracker_item->pkey_hash = l_vote_pkey_hash;
                assert(compare256(l_value, l_moved_value) > 0);
                SUBTRACT_256_256(l_value, l_moved_value, &l_tracker_item->coloured_value);
                l_vote_add = false;
            }
            l_tx_item->out_metadata[i].trackers = dap_list_append(l_tx_item->out_metadata[i].trackers, l_tracker);

        }
        if (!l_voting_found && l_vote_tx_item) {
            dap_ledger_tracker_t *l_new_tracker = DAP_NEW_Z(dap_ledger_tracker_t);
            dap_ledger_tracker_item_t *l_item_new = DAP_NEW_Z(dap_ledger_tracker_item_t);
            if (!l_new_tracker || !l_item_new) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                l_ret = DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
                goto FIN;
            }
            l_new_tracker->voting_hash = l_vote_tx_item->voting_hash;
            l_item_new->pkey_hash = l_vote_pkey_hash;
            l_item_new->coloured_value = l_value;
            DL_APPEND(l_new_tracker->items, l_item_new);
            l_tx_item->out_metadata[i].trackers = dap_list_append(l_tx_item->out_metadata[i].trackers, l_new_tracker);
        }
    }

    // add transaction to the cache list
    if (l_multichannel)
        l_tx_item->cache_data.flags |= LEDGER_PVT_TX_META_FLAG_MULTICHANNEL;
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
            l_notify->callback(a_ledger, a_tx, &l_tx_hash, l_notify->arg, DAP_LEDGER_NOTIFY_OPCODE_ADDED);
        }
    }
    if ( is_ledger_cached(l_ledger_pvt) ) {
        // Add it to cache
        size_t l_cache_size = sizeof(l_tx_item->cache_data) + l_tx_item->cache_data.n_outs * sizeof(dap_chain_hash_fast_t);
        size_t l_tx_cache_sz = l_tx_size + l_cache_size + sizeof(dap_ledger_cache_gdb_record_t);
        dap_ledger_cache_gdb_record_t *l_tx_cache = DAP_NEW_STACK_SIZE(dap_ledger_cache_gdb_record_t, l_tx_cache_sz);
        *l_tx_cache = (dap_ledger_cache_gdb_record_t) { .cache_size = l_cache_size, .datum_size = l_tx_size };
        memcpy(l_tx_cache->data, &l_tx_item->cache_data, l_cache_size);
        memcpy(l_tx_cache->data + l_cache_size, a_tx, l_tx_size);
        l_cache_used_outs[0] = (dap_store_obj_t) {
                .key        = l_tx_hash_str,
                .value      = (byte_t*)l_tx_cache,
                .value_len  = l_tx_cache_sz,
                .group      = l_ledger_cache_group,
                .timestamp  = dap_nanotime_now()
        };
        // Apply it with single DB transaction
        if (dap_global_db_set_raw(l_cache_used_outs, l_outs_used + 1, NULL, NULL))
            debug_if(g_debug_ledger, L_WARNING, "Ledger cache mismatch");
    }
    if (!a_from_threshold && is_ledger_threshld(l_ledger_pvt))
        dap_ledger_pvt_threshold_txs_proc(a_ledger);
FIN:
    if (l_trackers_mover)
        dap_list_free_full(l_trackers_mover, s_trackers_clear);
    if (l_list_bound_items)
        dap_list_free_full(l_list_bound_items, NULL);
    if (l_list_tx_out)
        dap_list_free(l_list_tx_out);
    if (l_values_from_cur_tx) {
        dap_ledger_tokenizer_t *it, *tmp;
        LL_FOREACH_SAFE(l_values_from_cur_tx, it, tmp)
            DAP_DELETE(it);
    }
    if ( is_ledger_cached(l_ledger_pvt) ) {
        if (l_cache_used_outs) {
            for (size_t i = 1; i < l_outs_used; ++i) {
                DAP_DEL_MULTY(l_cache_used_outs[i].key, l_cache_used_outs[i].value);
            }
        }
        DAP_DEL_MULTY(l_cache_used_outs, l_ledger_cache_group);
    }
    return l_ret;
}

int dap_ledger_tx_balance_update(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash, uint32_t a_out_num)
{
    dap_return_val_if_fail(a_ledger && a_tx_hash, -1);
    dap_chain_datum_tx_t *l_tx = dap_ledger_tx_unspent_find_by_hash(a_ledger, a_tx_hash);
    if (!l_tx) {
        log_it(L_ERROR, "Can't find tx %s in ledger for unlock balance", dap_hash_fast_to_str_static(a_tx_hash));
        return -2;
    }
    uint8_t *l_locked_out = dap_chain_datum_tx_item_get_nth(l_tx, TX_ITEM_TYPE_OUT_ALL, a_out_num);
    if (!l_locked_out || *l_locked_out != TX_ITEM_TYPE_OUT_STD) {
        log_it(L_ERROR, "Can't find out number %u in tx %s for unlock balance", a_out_num, dap_hash_fast_to_str_static(a_tx_hash));
        return -3;
    }
    dap_chain_tx_out_std_t *l_out_std = (dap_chain_tx_out_std_t *)l_locked_out;
    if (!l_out_std->ts_unlock || l_out_std->ts_unlock > (PVT(a_ledger)->blockchain_time)) {
        log_it(L_ERROR, "Can't unloack out number %u in tx %s", a_out_num, dap_hash_fast_to_str_static(a_tx_hash));
        return -4;
    }
    return s_balance_update_for_addr(a_ledger, &l_out_std->addr, l_out_std->token, l_out_std->value);
}

/**
 * @brief Remove transaction from the cache list
 * @param a_ledger
 * @param a_tx
 * @param a_tx_hash
 * @param a_from_threshold
 * @return return 1 OK, -1 error
 */
int dap_ledger_tx_remove(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, dap_time_t a_cur_block_timestamp)
{
    int l_ret = 0;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_list_t *l_list_bound_items = NULL;
    dap_list_t *l_list_tx_out = NULL;
    dap_chain_srv_uid_t l_tag =  { .uint64 = 0 };
    dap_chain_tx_tag_action_type_t l_action = DAP_CHAIN_TX_TAG_ACTION_UNKNOWN;
    char l_main_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX] = { '\0' };

    char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(a_tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));

    // Get boundary items list into l_list_bound_items
    // Get tx outs list into l_list_tx_out
    int l_ret_check;
    if( (l_ret_check = s_tx_cache_check(a_ledger, a_tx, a_tx_hash, false,
                                                       &l_list_bound_items, &l_list_tx_out,
                                                       l_main_token_ticker, NULL, &l_tag, &l_action, true))) {
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
    if ( is_ledger_cached(l_ledger_pvt) ) {
        l_cache_used_outs = DAP_NEW_Z_COUNT(dap_store_obj_t, l_outs_used);
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
                debug_if(g_debug_ledger, L_DEBUG, "REFUND %s from addr: %s because tx was removed.",
                         dap_uint256_to_char(l_bound_item->value, NULL), l_wallet_balance_key);
                SUM_256_256(wallet_balance->balance, l_bound_item->value, &wallet_balance->balance);
                // Update the cache
                s_balance_cache_update(a_ledger, wallet_balance);
            } else {
                debug_if(g_debug_ledger, L_ERROR, "!!! Attempt to SPEND from some non-existent balance !!!: %s %s", l_addr_str, l_cur_token_ticker);
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
            if (l_verificator && l_verificator->callback_in_delete)
                l_verificator->callback_in_delete(a_ledger, a_tx, a_tx_hash, l_bound_item->cond);
        } break;

        default:
            log_it(L_ERROR, "Unknown item type %d in ledger TX bound for IN part", l_type);
            break;
        }

        // add a used output
        dap_ledger_tx_item_t *l_prev_item_out = l_bound_item->prev_item;
        l_prev_item_out->out_metadata[l_bound_item->prev_out_idx].tx_spent_hash_fast = (dap_hash_fast_t){ };
        l_prev_item_out->cache_data.n_outs_used--;
        if ( is_ledger_cached(l_ledger_pvt) ) {
            // mirror it in the cache
            size_t l_tx_size = dap_chain_datum_tx_get_size(l_prev_item_out->tx);
            size_t l_cache_size = sizeof(l_prev_item_out->cache_data) + l_prev_item_out->cache_data.n_outs * sizeof(dap_chain_hash_fast_t);
            size_t l_tx_cache_sz = l_tx_size + l_cache_size + sizeof(dap_ledger_cache_gdb_record_t);
            dap_ledger_cache_gdb_record_t *l_tx_cache = DAP_NEW_Z_SIZE(dap_ledger_cache_gdb_record_t, l_tx_cache_sz);
            l_tx_cache->cache_size = l_cache_size;
            l_tx_cache->datum_size = l_tx_size;
            memcpy(l_tx_cache->data, &l_prev_item_out->cache_data, l_cache_size);
            memcpy(l_tx_cache->data + l_cache_size, l_prev_item_out->tx, l_tx_size);
            l_cache_used_outs[l_spent_idx] = (dap_store_obj_t) {
                    .key        = dap_chain_hash_fast_to_str_new(&l_prev_item_out->tx_hash_fast),
                    .value      = (byte_t*)l_tx_cache,
                    .value_len  = l_tx_cache_sz,
                    .group      = l_ledger_cache_group,
                    .timestamp  = 0
            };
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
            if (l_verificator && l_verificator->callback_out_delete)
                l_verificator->callback_out_delete(a_ledger, a_tx, a_tx_hash, l_cond);
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
        case TX_ITEM_TYPE_OUT_STD: {
            dap_chain_tx_out_std_t *l_out_item_std = (dap_chain_tx_out_std_t *)l_tx_out->data;
            l_addr = l_out_item_std->ts_unlock < PVT(a_ledger)->blockchain_time ? &l_out_item_std->addr : NULL;
            l_value = l_out_item_std->value;
            l_cur_token_ticker = l_out_item_std->token;
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
        debug_if(g_debug_ledger, L_DEBUG, "UNDO %s from addr: %s", dap_uint256_to_char(l_value, NULL), l_wallet_balance_key);
        pthread_rwlock_rdlock(&l_ledger_pvt->balance_accounts_rwlock);
        HASH_FIND_STR(PVT(a_ledger)->balance_accounts, l_wallet_balance_key, wallet_balance);
        pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
        if (wallet_balance) {
            SUBTRACT_256_256(wallet_balance->balance, l_value, &wallet_balance->balance);
            // Update the cache
            s_balance_cache_update(a_ledger, wallet_balance);
        } else
            log_it(L_CRITICAL, "Wallet is not presented in cache. Can't substract out value from balance.");
        DAP_DELETE(l_wallet_balance_key);
    }

    if (s_voting_callbacks.voting_delete_callback) {
        if (l_action == DAP_CHAIN_TX_TAG_ACTION_VOTING)
            s_voting_callbacks.voting_delete_callback(a_ledger, TX_ITEM_TYPE_VOTING, a_tx, a_tx_hash);
        else if (l_action == DAP_CHAIN_TX_TAG_ACTION_VOTE)
            s_voting_callbacks.voting_delete_callback(a_ledger, TX_ITEM_TYPE_VOTE, a_tx, a_tx_hash);
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
    if (l_tx_item) {
        DL_FOREACH(PVT(a_ledger)->tx_add_notifiers, l_notifier) {
            dap_ledger_tx_notifier_t *l_notify = l_notifier->data;
            l_notify->callback(l_notify->arg, a_ledger, l_tx_item->tx, DAP_LEDGER_NOTIFY_OPCODE_DELETED);
        }
    }
    if (l_cross_network) {
        DL_FOREACH(PVT(a_ledger)->bridged_tx_notifiers, l_notifier) {
            dap_ledger_bridged_tx_notifier_t *l_notify = l_notifier->data;
            l_notify->callback(a_ledger, a_tx, a_tx_hash, l_notify->arg, DAP_LEDGER_NOTIFY_OPCODE_DELETED);
        }
    }

    // Clear & destroy item
    for (uint32_t i = 0; i < l_tx_item->cache_data.n_outs; i++)
        dap_list_free_full(l_tx_item->out_metadata[i].trackers, dap_ledger_colour_clear_callback);
    DAP_DELETE(l_tx_item);

    if ( is_ledger_cached(l_ledger_pvt) ) {
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
    if ( is_ledger_cached(l_ledger_pvt) ) {
        if (l_cache_used_outs) {
            for (size_t i = 1; i < l_outs_used; i++) {
                DAP_DELETE(l_cache_used_outs[i].key);
                DAP_DELETE(l_cache_used_outs[i].value);
            }
        }
        DAP_DELETE(l_cache_used_outs);
        DAP_DELETE(l_ledger_cache_group);
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
    if (!is_ledger_cached(PVT(a_ledger)))
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
 * Get the transaction in the cache by the addr in out item
 *
 * a_public_key[in] public key that signed the transaction
 * a_public_key_size[in] public key size
 * a_tx_first_hash [in/out] hash of the initial transaction/ found transaction, if 0 start from the beginning
 */
dap_chain_datum_tx_t* dap_ledger_tx_find_by_addr(dap_ledger_t *a_ledger , const char * a_token ,
        const dap_chain_addr_t *a_addr, dap_chain_hash_fast_t *a_tx_first_hash)
{
    if(!a_addr || !a_tx_first_hash)
        return NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);

    bool is_tx_found = false;
    dap_ledger_tx_item_t *l_iter_start = NULL, *l_iter_current, *l_item_tmp;
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    if (!dap_hash_fast_is_blank(a_tx_first_hash)) {
        HASH_FIND(hh, l_ledger_pvt->ledger_items, a_tx_first_hash, sizeof(dap_hash_t), l_iter_start);
        if (!l_iter_start || !l_iter_start->hh.next){
            pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
            return NULL;            
        }
         // start searching from the next hash after a_tx_first_hash
        l_iter_start = l_iter_start->hh.next;
    } else
        l_iter_start = l_ledger_pvt->ledger_items;
    HASH_ITER(hh, l_iter_start, l_iter_current, l_item_tmp) {
        // If a_token is setup we check if its not our token - miss it
        if (a_token && *l_iter_current->cache_data.token_ticker &&
                dap_strcmp(l_iter_current->cache_data.token_ticker, a_token) &&
                !(l_iter_current->cache_data.flags & LEDGER_PVT_TX_META_FLAG_MULTICHANNEL))
            continue;
        // Now work with it
        dap_chain_datum_tx_t *l_tx = l_iter_current->tx;
        dap_chain_hash_fast_t *l_tx_hash = &l_iter_current->tx_hash_fast;
        // Get 'out' items from transaction
        byte_t *it; size_t l_size;
        TX_ITEM_ITER_TX(it, l_size, l_tx) {
            dap_chain_addr_t l_addr = { };
            switch (*it) {
            case TX_ITEM_TYPE_OUT:
                l_addr = ((dap_chain_tx_out_t*)it)->addr;
                break;
            case TX_ITEM_TYPE_OUT_OLD:
                l_addr = ((dap_chain_tx_out_old_t*)it)->addr;
                break;
            case TX_ITEM_TYPE_OUT_EXT:
                if ( a_token && dap_strcmp(a_token, ((dap_chain_tx_out_ext_t*)it)->token) )
                    continue;
                l_addr = ((dap_chain_tx_out_ext_t*)it)->addr;
                break;
            case TX_ITEM_TYPE_OUT_STD:
                if (a_token && dap_strcmp(a_token, ((dap_chain_tx_out_std_t *)it)->token))
                    continue;
                l_addr = ((dap_chain_tx_out_std_t *)it)->addr;
                break;
            default:
                continue;
            }
            if ( dap_chain_addr_compare(a_addr, &l_addr) ) {
                *a_tx_first_hash = *l_tx_hash;
                is_tx_found = true;
                break;
            }
        }
        if (is_tx_found)
            break;
    }
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    return is_tx_found ? l_iter_current->tx : NULL;
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
    dap_hash_fast_t l_hash = *a_tx_hash;
    dap_chain_datum_tx_t *l_prev_tx = NULL;
    while ( (l_prev_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_hash)) ) {
        byte_t *l_iter = l_prev_tx->tx_items;
        dap_chain_tx_in_cond_t *l_cond_in = NULL;
        while ( (l_cond_in = (dap_chain_tx_in_cond_t *)dap_chain_datum_tx_item_get(l_prev_tx, NULL, l_iter, TX_ITEM_TYPE_IN_COND, NULL)) ) {
            dap_hash_fast_t l_hash_tmp = l_cond_in->header.tx_prev_hash;
            if ( (l_prev_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_hash_tmp)) &&
                    dap_chain_datum_tx_out_cond_get(l_prev_tx, a_cond_type, NULL) ) {
                l_hash = l_hash_tmp;
                break;
            }
        }
        if (!l_cond_in)
            break;
    }
    return l_hash;
}

dap_hash_fast_t dap_ledger_get_final_chain_tx_hash(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_subtype_t a_cond_type, dap_chain_hash_fast_t *a_tx_hash, bool a_unspent_only)
{
    dap_return_val_if_fail(a_ledger && a_tx_hash, (dap_hash_fast_t) {});
    dap_chain_datum_tx_t *l_tx = NULL;
    dap_chain_hash_fast_t l_hash = *a_tx_hash;
    dap_ledger_tx_item_t *l_item = NULL;
    while (( l_tx = s_tx_find_by_hash(a_ledger, &l_hash, &l_item, false) )) {
        int l_out_num = 0;
        if (!dap_chain_datum_tx_out_cond_get(l_tx, a_cond_type, &l_out_num))
            return a_unspent_only ? (dap_hash_fast_t){} : l_hash;
        else if (dap_hash_fast_is_blank(&l_item->out_metadata[l_out_num].tx_spent_hash_fast))
            break;
        l_hash = l_item->out_metadata[l_out_num].tx_spent_hash_fast;
    }
    return l_hash;
}

/**
 * Check whether used 'out' items (local function)
 */
static bool s_ledger_tx_hash_is_used_out_item(dap_ledger_tx_item_t *a_item, uint32_t a_idx_out, dap_hash_fast_t *a_out_spender_hash)
{
    dap_return_val_if_fail(a_item && a_item->cache_data.n_outs, true);
    // if there are used 'out' items
    if ((a_item->cache_data.n_outs_used >= a_idx_out) && !dap_hash_fast_is_blank(&(a_item->out_metadata[a_idx_out].tx_spent_hash_fast))) {
        if (a_out_spender_hash)
            *a_out_spender_hash = a_item->out_metadata[a_idx_out].tx_spent_hash_fast;
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
    s_tx_find_by_hash(a_ledger, a_tx_hash, &l_item_out, false);
    return l_item_out ? s_ledger_tx_hash_is_used_out_item(l_item_out, a_idx_out, a_out_spender) : true;
}

dap_list_t *dap_ledger_tx_get_trackers(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash, uint32_t a_out_idx)
{
    dap_list_t *ret = NULL;
    dap_ledger_tx_item_t *l_item_out = NULL;
    s_tx_find_by_hash(a_ledger, a_tx_hash, &l_item_out, false);
    if (!l_item_out || l_item_out->cache_data.n_outs < a_out_idx)
        return ret;
    return l_item_out->out_metadata[a_out_idx].trackers;
}

uint256_t dap_ledger_coin_get_uncoloured_value(dap_ledger_t *a_ledger, dap_hash_fast_t *a_voting_hash,
                                               dap_hash_fast_t *a_tx_hash, int a_out_idx,
                                               dap_hash_fast_t *a_pkey_hash)
{
    dap_return_val_if_fail(a_ledger && a_voting_hash && a_tx_hash, uint256_0);
    dap_ledger_tx_item_t *l_item_out = NULL;
    dap_chain_datum_tx_t *l_tx = s_tx_find_by_hash(a_ledger, a_tx_hash, &l_item_out, false);
    if (!l_item_out || l_item_out->cache_data.n_outs <= (uint32_t)a_out_idx ||
            !dap_hash_fast_is_blank(&(l_item_out->out_metadata[a_out_idx].tx_spent_hash_fast)))
        return uint256_0;
    uint8_t *l_out = dap_chain_datum_tx_item_get_nth(l_tx, TX_ITEM_TYPE_OUT_ALL, a_out_idx);
    assert(l_out);
    uint256_t l_value = {};
    switch (*l_out) {
    case TX_ITEM_TYPE_OUT_OLD:
        l_value = GET_256_FROM_64(((dap_chain_tx_out_old_t *)l_out)->header.value);
        break;
    case TX_ITEM_TYPE_OUT:
        l_value = ((dap_chain_tx_out_t *)l_out)->header.value;
        break;
    case TX_ITEM_TYPE_OUT_EXT:
        l_value = ((dap_chain_tx_out_ext_t *)l_out)->header.value;
        break;
    case TX_ITEM_TYPE_OUT_STD:
        l_value = ((dap_chain_tx_out_std_t *)l_out)->value;
        break;
    case TX_ITEM_TYPE_OUT_COND:
        l_value = ((dap_chain_tx_out_cond_t *)l_out)->header.value;
        break;
    default:
        assert(false);
        return uint256_0;
    }
    for (dap_list_t *it = l_item_out->out_metadata[a_out_idx].trackers; it ; it = it->next) {
        dap_ledger_tracker_t *l_tracker = it->data;
        if (dap_hash_fast_compare(&l_tracker->voting_hash, a_voting_hash)) {
            uint256_t l_coloured_value = {};
            dap_ledger_tracker_item_t *l_item;
            DL_FOREACH(l_tracker->items, l_item)
                if (!a_pkey_hash || !dap_hash_fast_compare(a_pkey_hash, &l_item->pkey_hash))
                    SUM_256_256(l_coloured_value, l_item->coloured_value, &l_coloured_value);
            assert(compare256(l_value, l_coloured_value) >= 0);
            SUBTRACT_256_256(l_value, l_coloured_value, &l_value);
            break;
        }
    }
    return l_value;
}

void dap_ledger_colour_clear_callback(void *a_list_data)
{
    dap_ledger_tracker_t *l_free = a_list_data;
    dap_ledger_tracker_item_t *it, *tmp;
    DL_FOREACH_SAFE(l_free->items, it, tmp)
        DAP_DELETE(it); // No need for DL_DELETE cause clear the full list
    DAP_DELETE(a_list_data);
}

void dap_ledger_tx_clear_colour(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash)
{
    dap_return_if_fail(a_ledger && a_tx_hash);
    dap_ledger_tx_item_t *l_item_out = NULL;
    dap_chain_datum_tx_t *l_tx = s_tx_find_by_hash(a_ledger, a_tx_hash, &l_item_out, false);
    if (!l_item_out) {
        log_it(L_ERROR, "Cna't find ledger tx item for hash %s", dap_hash_fast_to_str_static(a_tx_hash));
        return;
    }
    l_item_out->cache_data.flags |= LEDGER_PVT_TX_META_FLAG_IMMUTABLE;
    for (uint32_t i = 0; i < l_item_out->cache_data.n_outs; i++) {
        if (!dap_hash_fast_is_blank(&l_item_out->out_metadata[i].tx_spent_hash_fast)) {
            dap_list_free_full(l_item_out->out_metadata[i].trackers, dap_ledger_colour_clear_callback);
            l_item_out->out_metadata[i].trackers = NULL;
        }
    }
}

void dap_ledger_tx_add_notify(dap_ledger_t *a_ledger, dap_ledger_tx_add_notify_t a_callback, void *a_arg)
{
    dap_return_if_fail(a_ledger && a_callback);
    dap_ledger_tx_notifier_t *l_notifier = DAP_NEW_Z_RET_IF_FAIL(dap_ledger_tx_notifier_t);
    *l_notifier = (dap_ledger_tx_notifier_t) { .callback = a_callback, .arg = a_arg };
    PVT(a_ledger)->tx_add_notifiers = dap_list_append(PVT(a_ledger)->tx_add_notifiers, l_notifier);
}

void dap_ledger_bridged_tx_notify_add(dap_ledger_t *a_ledger, dap_ledger_bridged_tx_notify_t a_callback, void *a_arg)
{
    dap_return_if_fail(a_ledger && a_callback);
    dap_ledger_bridged_tx_notifier_t *l_notifier = DAP_NEW_Z_RET_IF_FAIL(dap_ledger_bridged_tx_notifier_t);
    *l_notifier = (dap_ledger_bridged_tx_notifier_t) { .callback = a_callback, .arg = a_arg };
    PVT(a_ledger)->bridged_tx_notifiers = dap_list_append(PVT(a_ledger)->bridged_tx_notifiers , l_notifier);
}

dap_chain_token_ticker_str_t dap_ledger_tx_calculate_main_ticker_(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, int *a_ledger_rc)
{
    dap_hash_fast_t l_tx_hash = dap_chain_node_datum_tx_calc_hash(a_tx);
    dap_chain_token_ticker_str_t l_ret = { };
    int l_rc = s_tx_cache_check(a_ledger, a_tx, &l_tx_hash, false, NULL, NULL, (char*)&l_ret, NULL, NULL, NULL, false);
    if (l_rc == DAP_LEDGER_CHECK_ALREADY_CACHED)
        dap_strncpy( (char*)&l_ret, dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_tx_hash), DAP_CHAIN_TICKER_SIZE_MAX );
    if (a_ledger_rc)
        *a_ledger_rc = l_rc;
    return l_ret;
}

// Add new verificator callback with associated subtype. Returns 1 if callback replaced, -1 error, overwise returns 0
int dap_ledger_verificator_add(dap_chain_tx_out_cond_subtype_t a_subtype,
                               dap_ledger_cond_in_verify_callback_t a_callback_in_verify, dap_ledger_cond_out_verify_callback_t a_callback_out_verify,
                               dap_ledger_cond_in_add_callback_t a_callback_in_add, dap_ledger_cond_out_add_callback_t a_callback_out_add,
                               dap_ledger_cond_in_delete_callback_t a_callback_in_delete, dap_ledger_cond_out_delete_callback_t a_callback_out_delete)
{
    dap_ledger_verificator_t *l_new_verificator = NULL;
    int l_tmp = (int)a_subtype;
    pthread_rwlock_rdlock(&s_verificators_rwlock);
    HASH_FIND_INT(s_verificators, &l_tmp, l_new_verificator);
    pthread_rwlock_unlock(&s_verificators_rwlock);
    if (!l_new_verificator)
        l_new_verificator = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_ledger_verificator_t, -1);
    else
        log_it(L_WARNING, "Verificator subtype %d already used, callbacks addresses will be replaced", a_subtype);
    *l_new_verificator = (dap_ledger_verificator_t) {
            .subtype = (int)a_subtype,
            .callback_in_verify = a_callback_in_verify, .callback_out_verify = a_callback_out_verify,
            .callback_in_add = a_callback_in_add, .callback_out_add = a_callback_out_add,
            .callback_in_delete = a_callback_in_delete, .callback_out_delete = a_callback_out_delete
        };
    pthread_rwlock_wrlock(&s_verificators_rwlock);
    HASH_ADD_INT(s_verificators, subtype, l_new_verificator);
    pthread_rwlock_unlock(&s_verificators_rwlock);
    return 0;
}

int dap_ledger_voting_verificator_add(dap_ledger_voting_callback_t a_voting_callback, dap_ledger_vote_callback_t a_vote_callback,
                                      dap_ledger_voting_delete_callback_t a_callback_delete, dap_ledger_voting_expire_callback_t a_callback_expire)
{
    dap_return_val_if_fail(a_voting_callback && a_vote_callback && a_callback_delete && a_callback_expire, -1);
    int ret = s_voting_callbacks.voting_callback || s_voting_callbacks.vote_callback ||
                s_voting_callbacks.voting_delete_callback || s_voting_callbacks.voting_expire_callback ? 1 : 0;
    s_voting_callbacks.voting_callback = a_voting_callback;
    s_voting_callbacks.vote_callback = a_vote_callback;
    s_voting_callbacks.voting_delete_callback = a_callback_delete;
    s_voting_callbacks.voting_expire_callback = a_callback_expire;
    return ret;
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
            case TX_ITEM_TYPE_OUT_STD: {
                dap_chain_tx_out_std_t *l_tx_out = (dap_chain_tx_out_std_t *)it;
                l_add = l_tx_out->value;
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
                &&  !dap_chain_datum_tx_verify_sign(l_cur_tx, 0)                            // Signs are valid
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

int s_compare_tracker_items_hardfork(dap_ledger_tracker_item_t *a_item1, dap_ledger_tracker_item_t *a_item2)
{
    return memcmp(&a_item1->pkey_hash, &a_item1->pkey_hash, sizeof(dap_hash_fast_t));
}

int s_compare_trackers_hardfork(dap_list_t *a_tracker1, dap_list_t *a_tracker2)
{
    dap_ledger_tracker_t *l_tracker1 = a_tracker1->data, *l_tracker2 = a_tracker2->data;
    return memcmp(&l_tracker1->voting_hash, &l_tracker2->voting_hash, sizeof(dap_hash_fast_t));
}

dap_list_t *s_trackers_aggregate_hardfork(dap_ledger_t *a_ledger, dap_list_t *a_trackers, dap_list_t *a_added, dap_time_t a_ts_creation_time)
{
    dap_return_val_if_fail(s_voting_callbacks.voting_expire_callback, a_trackers);
    for (dap_list_t *it = a_added; it; it = it->next) {
        dap_ledger_tracker_t *l_new_tracker = it->data, *l_exists_tracker = NULL;
        dap_time_t l_exp_time = s_voting_callbacks.voting_expire_callback(a_ledger, &l_new_tracker->voting_hash);
        if (a_ts_creation_time > l_exp_time)    // Don't track expired votings
            continue;
        dap_list_t *l_exists = dap_list_find(a_trackers, &l_new_tracker->voting_hash, s_compare_trackers_hardfork);
        if (!l_exists) {
            l_exists_tracker = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_ledger_tracker_t, a_trackers);
            l_exists_tracker->voting_hash = l_new_tracker->voting_hash;
            a_trackers = dap_list_append(a_trackers, l_exists_tracker);
        } else
            l_exists_tracker = l_exists->data;
        dap_ledger_tracker_item_t *l_item, *l_exists_item;
        DL_FOREACH(l_new_tracker->items, l_item) {
            dap_ledger_tracker_item_t l_sought = { .pkey_hash = l_item->pkey_hash };
            DL_SEARCH(l_exists_tracker->items, l_exists_item, &l_sought, s_compare_tracker_items_hardfork);
            if (!l_exists_item) {
                l_exists_item = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_ledger_tracker_item_t, a_trackers);
                l_exists_item->pkey_hash = l_item->pkey_hash;
                DL_APPEND(l_exists_tracker->items, l_exists_item);
            }
            if (SUM_256_256(l_exists_item->coloured_value, l_item->coloured_value, &l_exists_item->coloured_value)) {
                log_it(L_ERROR, "Tracking value overflow, can't track voting %s for hardfork", dap_hash_fast_to_str_static(&l_new_tracker->voting_hash));
                return a_trackers;
            }
        }
    }
    return a_trackers;
}

static int s_aggregate_out(dap_ledger_hardfork_balances_t **a_out_list, dap_ledger_t *a_ledger,
                           const char *a_ticker, dap_chain_addr_t *a_addr,
                           uint256_t a_value, dap_time_t a_hardfork_start_time,
                           dap_list_t *a_trackers)
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
    l_exist->trackers = s_trackers_aggregate_hardfork(a_ledger, l_exist->trackers, a_trackers, a_hardfork_start_time);
    return 0;
}

static int s_aggregate_out_cond(dap_ledger_hardfork_condouts_t **a_ret_list, dap_ledger_t *a_ledger,
                                dap_chain_tx_out_cond_t *a_out_cond, dap_chain_tx_sig_t *a_sign,
                                dap_hash_fast_t *a_tx_hash, const char *a_token_ticker,
                                dap_time_t a_hardfork_start_time, dap_list_t *a_trackers)
{
    dap_ledger_hardfork_condouts_t *l_new_condout = DAP_NEW_Z(dap_ledger_hardfork_condouts_t);
    if (!l_new_condout) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -1;
    }
    *l_new_condout = (dap_ledger_hardfork_condouts_t) { .hash = *a_tx_hash, .cond = a_out_cond, .sign = a_sign };
    dap_strncpy(l_new_condout->ticker, a_token_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
    l_new_condout->trackers = s_trackers_aggregate_hardfork(a_ledger, NULL, a_trackers, a_hardfork_start_time);
    DL_APPEND(*a_ret_list, l_new_condout);
    return 0;
}

static dap_chain_addr_t* s_change_addr(struct json_object *a_json, dap_chain_addr_t *a_addr)
{
    if(!a_json || !a_addr)
        return NULL;
    const char * l_out_addr = dap_chain_addr_to_str_static(a_addr);
    struct json_object *l_json = json_object_object_get(a_json, l_out_addr);
    if(l_json && json_object_is_type(l_json, json_type_string)) {
        const char *l_change_str =  json_object_get_string(l_json);
        dap_chain_addr_t* l_ret_addr =  dap_chain_addr_from_str(l_change_str);
        DAP_DELETE(l_change_str);
        return l_ret_addr;
    }
    return NULL;
}

dap_ledger_hardfork_balances_t *dap_ledger_states_aggregate(dap_ledger_t *a_ledger, dap_time_t a_hardfork_decree_creation_time, dap_ledger_hardfork_condouts_t **l_cond_outs_list, json_object *a_changed_addrs)
{
    dap_return_val_if_fail(a_ledger, NULL);
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
            if (!dap_hash_fast_is_blank(&it->out_metadata[j].tx_spent_hash_fast)) {
                j++;
                continue;
            }
            dap_list_t *l_trackers = it->out_metadata[j++].trackers;
            uint8_t l_tx_item_type = *l_tx_item;
            switch(l_tx_item_type) {
            case TX_ITEM_TYPE_OUT: {
                dap_chain_tx_out_t *l_out = (dap_chain_tx_out_t *)l_tx_item;
                dap_chain_addr_t * l_change_addr = s_change_addr(a_changed_addrs, &l_out->addr);
                s_aggregate_out(&ret, a_ledger, it->cache_data.token_ticker, l_change_addr ? l_change_addr : &l_out->addr, l_out->header.value, a_hardfork_decree_creation_time, l_trackers);
                DAP_DEL_Z(l_change_addr);
                break;
            }
            case TX_ITEM_TYPE_OUT_OLD: {
                dap_chain_tx_out_old_t *l_out = (dap_chain_tx_out_old_t *)l_tx_item;
                dap_chain_addr_t * l_change_addr = s_change_addr(a_changed_addrs, &l_out->addr);
                s_aggregate_out(&ret, a_ledger, it->cache_data.token_ticker, l_change_addr ? l_change_addr : &l_out->addr, GET_256_FROM_64(l_out->header.value), a_hardfork_decree_creation_time, l_trackers);
                DAP_DEL_Z(l_change_addr);
                break;
            }
            case TX_ITEM_TYPE_OUT_EXT: {
                dap_chain_tx_out_ext_t *l_out = (dap_chain_tx_out_ext_t *)l_tx_item;
                dap_chain_addr_t * l_change_addr = s_change_addr(a_changed_addrs, &l_out->addr);
                s_aggregate_out(&ret, a_ledger, l_out->token, l_change_addr ? l_change_addr : &l_out->addr, l_out->header.value, a_hardfork_decree_creation_time, l_trackers);
                DAP_DEL_Z(l_change_addr);
                break;
            }
            case TX_ITEM_TYPE_OUT_STD: {
                dap_chain_tx_out_std_t *l_out = (dap_chain_tx_out_std_t *)l_tx_item;
                dap_chain_addr_t * l_change_addr = s_change_addr(a_changed_addrs, &l_out->addr);
                s_aggregate_out(&ret, a_ledger, l_out->token, l_change_addr ? l_change_addr : &l_out->addr, l_out->value, a_hardfork_decree_creation_time, l_trackers);
                DAP_DEL_Z(l_change_addr);
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
                dap_chain_tx_sig_t *l_tx_sign = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get_nth(l_tx, TX_ITEM_TYPE_SIG, 0);
                if (!l_tx_sign) {
                    log_it(L_ERROR, "Can't find sign for conditional TX %s", dap_hash_fast_to_str_static(&l_first_tx_hash));
                    continue;
                }
                s_aggregate_out_cond(&l_cond_ret, a_ledger, l_out, l_tx_sign, &it->tx_hash_fast, it->cache_data.token_ticker, a_hardfork_decree_creation_time, l_trackers);
                break;
            }
            default:
                log_it(L_ERROR, "Unexpected item type %hhu", l_tx_item_type);
                break;
            }
        }
    }
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    if (l_cond_outs_list)
        *l_cond_outs_list = l_cond_ret;
    return ret;
}
