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
#include "dap_json.h"

#define LOG_TAG "dap_ledger_token"

dap_ledger_token_item_t *dap_ledger_pvt_find_token(dap_ledger_t *a_ledger, const char *a_token_ticker)
{
    dap_return_val_if_fail(a_ledger && a_token_ticker, NULL);
    dap_ledger_token_item_t *l_token_item = NULL;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    HASH_FIND_STR(PVT(a_ledger)->tokens, a_token_ticker, l_token_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    return l_token_item;
}

/**
 * @brief GDB callback for loaded emissions from cache
 * @param a_global_db_context
 * @param a_rc
 * @param a_group
 * @param a_key
 * @param a_values_total
 * @param a_values_shift
 * @param a_values_count
 * @param a_values
 * @param a_arg
 * @return Always true thats means to clear up a_values
 */
static bool s_load_cache_gdb_loaded_emissions_callback(dap_global_db_instance_t *a_dbi,
                                                       int a_rc, const char *a_group,
                                                       const size_t a_values_total, const size_t a_values_count,
                                                       dap_global_db_obj_t *a_values, void *a_arg)
{
    dap_ledger_t * l_ledger = (dap_ledger_t*) a_arg;
    dap_ledger_private_t * l_ledger_pvt = PVT(l_ledger);

    for (size_t i = 0; i < a_values_count; i++) {
        if (a_values[i].value_len <= sizeof(dap_hash_fast_t))
            continue;
        const char *c_token_ticker = ((dap_chain_datum_token_emission_t *)
                                      (a_values[i].value + sizeof(dap_hash_fast_t)))->hdr.ticker;
        dap_ledger_token_item_t *l_token_item = NULL;
        HASH_FIND_STR(l_ledger_pvt->tokens, c_token_ticker, l_token_item);
        if (!l_token_item) {
            log_it(L_WARNING, "Not found token with ticker [%s], need to 'ledger reload' to update cache", c_token_ticker);
            continue;
        }
        dap_ledger_token_emission_item_t *l_emission_item = DAP_NEW_Z(dap_ledger_token_emission_item_t);
        if ( !l_emission_item ) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return false;
        }
        dap_chain_hash_fast_from_str(a_values[i].key, &l_emission_item->datum_token_emission_hash);
        l_emission_item->tx_used_out = *(dap_hash_fast_t*)a_values[i].value;
        l_emission_item->datum_token_emission = DAP_DUP_SIZE(a_values[i].value + sizeof(dap_hash_fast_t),
                                                             a_values[i].value_len - sizeof(dap_hash_fast_t));
        l_emission_item->datum_token_emission_size = a_values[i].value_len - sizeof(dap_hash_fast_t);
        HASH_ADD(hh, l_token_item->token_emissions, datum_token_emission_hash,
                 sizeof(dap_chain_hash_fast_t), l_emission_item);
    }

    char* l_gdb_group = dap_ledger_get_gdb_group(l_ledger, DAP_LEDGER_STAKE_LOCK_STR);
    dap_global_db_get_all(l_gdb_group, 0, dap_ledger_pvt_cache_gdb_load_stake_lock_callback, l_ledger);
    DAP_DELETE(l_gdb_group);
    return true;
}


/**
 * @brief s_load_cache_gdb_loaded_callback
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
bool dap_ledger_pvt_cache_gdb_load_tokens_callback(dap_global_db_instance_t *a_dbi,
                                                    int a_rc, const char *a_group,
                                                    const size_t a_values_total, const size_t a_values_count,
                                                    dap_global_db_obj_t *a_values, void *a_arg)
{
    dap_ledger_t *l_ledger = (dap_ledger_t *) a_arg;
    dap_ledger_private_t *l_ledger_pvt = PVT(l_ledger);
    if(a_rc) {
        log_it(L_NOTICE, "No ledger cache found");
        pthread_mutex_lock(&l_ledger_pvt->load_mutex);
        l_ledger_pvt->load_end = true;
        pthread_cond_broadcast(&l_ledger_pvt->load_cond );
        pthread_mutex_unlock(&l_ledger_pvt->load_mutex);

    }
    for (size_t i = 0; i < a_values_count; i++) {
        if (a_values[i].value_len <= sizeof(uint256_t))
            continue;
        dap_chain_datum_token_t *l_token = (dap_chain_datum_token_t *)(a_values[i].value + sizeof(uint256_t));
        size_t l_token_size = a_values[i].value_len - sizeof(uint256_t);
        if (strcmp(l_token->ticker, a_values[i].key)) {
            log_it(L_WARNING, "Corrupted token with ticker [%s], need to 'ledger reload' to update cache", a_values[i].key);
            continue;
        }
        dap_ledger_token_add(l_ledger, (byte_t *)l_token, l_token_size, dap_time_now());
        dap_ledger_token_item_t *l_token_item = dap_ledger_pvt_find_token(l_ledger, l_token->ticker);
        if (l_token_item)
            l_token_item->current_supply = *(uint256_t*)a_values[i].value;
    }

    char *l_gdb_group = dap_ledger_get_gdb_group(l_ledger, DAP_LEDGER_EMISSIONS_STR);
    dap_global_db_get_all(l_gdb_group, 0, s_load_cache_gdb_loaded_emissions_callback, l_ledger);
    DAP_DELETE(l_gdb_group);
    return true;
}

/**
 * @brief s_token_tsd_parse
 *
 * @param a_ledger
 * @param a_item_apply_to
 * @param a_token
 * @param a_token_size
 * @return int
 */
static int s_token_tsd_parse(dap_ledger_token_item_t *a_item_apply_to, dap_chain_datum_token_t *a_current_datum,
                             dap_ledger_t *a_ledger, byte_t *a_tsd, size_t a_tsd_total_size, bool a_apply)
{
    if (!a_tsd_total_size) {
        debug_if(a_item_apply_to, L_NOTICE, "No TSD sections in datum token");
        return DAP_LEDGER_CHECK_OK;
    }
    dap_return_val_if_pass(a_apply && !a_item_apply_to, DAP_LEDGER_CHECK_INVALID_ARGS);
    size_t l_new_signs_valid = a_item_apply_to ? a_item_apply_to->auth_signs_valid : 0;
    size_t l_new_signs_total = a_item_apply_to ? a_item_apply_to->auth_signs_total : 0;
    dap_pkey_t **l_new_pkeys = NULL;
    dap_hash_fast_t *l_new_pkey_hashes = NULL;
    bool l_was_pkeys_copied = false;
    size_t l_new_tx_recv_allow_size = a_item_apply_to ? a_item_apply_to->tx_recv_allow_size : 0;
    size_t l_new_tx_recv_block_size = a_item_apply_to ? a_item_apply_to->tx_recv_block_size : 0;
    size_t l_new_tx_send_allow_size = a_item_apply_to ? a_item_apply_to->tx_send_allow_size : 0;
    size_t l_new_tx_send_block_size = a_item_apply_to ? a_item_apply_to->tx_send_block_size : 0;
    struct spec_address *l_new_tx_recv_allow = NULL, *l_new_tx_recv_block = NULL,
                        *l_new_tx_send_allow = NULL, *l_new_tx_send_block = NULL;
    bool l_was_tx_recv_allow_copied = false, l_was_tx_recv_block_copied = false,
         l_was_tx_send_allow_copied = false, l_was_tx_send_block_copied = false;

#define m_ret_cleanup(ret_code) ({                          \
    DAP_DEL_ARRAY(l_new_pkeys, l_new_signs_total);          \
    DAP_DEL_MULTY(l_new_tx_recv_allow, l_new_tx_recv_block, \
                  l_new_tx_send_allow, l_new_tx_send_block, \
                  l_new_pkeys, l_new_pkey_hashes);          \
    ret_code; })
    uint64_t l_tsd_size = 0;
    dap_tsd_t *l_tsd = (dap_tsd_t *)a_tsd;
    for (uint64_t l_offset = 0; l_offset < a_tsd_total_size; l_offset += l_tsd_size) {
        if (l_offset + sizeof(dap_tsd_t) > a_tsd_total_size || l_offset + sizeof(dap_tsd_t) < l_offset) {
            log_it(L_WARNING, "Incorrect TSD section size, less than header");
            return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
        }
        l_tsd = (dap_tsd_t *)((byte_t *)l_tsd + l_tsd_size);
        l_tsd_size = dap_tsd_size(l_tsd);
        if (l_offset + l_tsd_size > a_tsd_total_size || l_offset + l_tsd_size < l_offset) {
            log_it(L_WARNING, "Wrong TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
            return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
        }
        switch (l_tsd->type) {
        // set flags
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_SET_FLAGS: {
            if (l_tsd->size != sizeof(uint16_t)) {
                log_it(L_WARNING, "Wrong SET_FLAGS TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            if (!a_apply)
                break;
            a_item_apply_to->flags |= dap_tsd_get_scalar(l_tsd, uint16_t);
        } break;

        // unset flags
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS: {
            if (l_tsd->size != sizeof(uint16_t)) {
                log_it(L_WARNING, "Wrong UNSET_FLAGS TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            if (!a_apply)
                break;
            a_item_apply_to->flags &= ~dap_tsd_get_scalar(l_tsd, uint16_t);
        } break;

        // set total supply
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY: { // 256
            if (l_tsd->size != sizeof(uint256_t)) {
                log_it(L_WARNING, "Wrong TOTAL_SUPPLY TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            if (!a_item_apply_to) {
                log_it(L_WARNING, "Unexpected TOTAL_SUPPLY TSD section in datum token declaration");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_FORBIDDEN);
            }
            uint256_t l_new_supply = dap_tsd_get_scalar(l_tsd, uint256_t);
            if (IS_ZERO_256(a_item_apply_to->total_supply)){
                log_it(L_WARNING, "Cannot update total_supply for token %s because the current value is set to infinity.", a_item_apply_to->ticker);
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_SUPPLY);
            }
            if (!IS_ZERO_256(l_new_supply) && compare256(a_item_apply_to->total_supply, l_new_supply) > -1) {
                log_it(L_WARNING, "Can't update token with ticker '%s' because the new 'total_supply' can't be smaller than the old one", a_item_apply_to->ticker);
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_SUPPLY);
            }
            if (!a_apply)
                break;
            uint256_t l_supply_delta = {};
            SUBTRACT_256_256(l_new_supply, a_item_apply_to->total_supply, &l_supply_delta); // TODO: deal with INF!
            a_item_apply_to->total_supply = l_new_supply;
            SUM_256_256(a_item_apply_to->current_supply, l_supply_delta, &a_item_apply_to->current_supply);
        } break;

        // Allowed tx receiver addres list add, remove or clear
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD: {
            if (l_tsd->size != sizeof(dap_chain_addr_t)) {
                log_it(L_WARNING, "Wrong TX_RECEIVER_ALLOWED_ADD TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            // Check if its correct
            dap_chain_addr_t *l_add_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            if (dap_chain_addr_check_sum(l_add_addr)) {
                log_it(L_WARNING, "Wrong address checksum in TSD param TX_RECEIVER_ALLOWED_ADD");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_ADDR);
            }
            if (!l_new_tx_recv_allow && l_new_tx_recv_allow_size && !l_was_tx_recv_allow_copied) {
                assert(a_item_apply_to->tx_recv_allow);
                // Deep copy addrs to sandbox
                l_new_tx_recv_allow = DAP_DUP_SIZE(a_item_apply_to->tx_recv_allow, l_new_tx_recv_allow_size * sizeof(struct spec_address));
                if (!l_new_tx_recv_allow) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_recv_allow_copied = true;
            // Check if its already present
            for (size_t i = 0; i < l_new_tx_recv_allow_size; i++) { // Check for all the list
                if (dap_chain_addr_compare(&l_new_tx_recv_allow[i].addr, l_add_addr)) { // Found
                    log_it(L_WARNING, "TSD param TX_RECEIVER_ALLOWED_ADD has address %s thats already present in list",
                                                                    dap_chain_addr_to_str_static(l_add_addr));
                    return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
                }
            }
            struct spec_address *l_tmp = DAP_REALLOC_COUNT_RET_VAL_IF_FAIL(l_new_tx_recv_allow, l_new_tx_recv_allow_size + 1, m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY));
            l_new_tx_recv_allow = l_tmp;
            l_new_tx_recv_allow[l_new_tx_recv_allow_size++].addr = *l_add_addr;
            l_new_tx_recv_allow[l_new_tx_recv_allow_size - 1].becomes_effective = dap_time_now();
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_REMOVE: {
            if (l_tsd->size != sizeof(dap_chain_addr_t)) {
                log_it(L_WARNING, "Wrong TX_RECEIVER_ALLOWED_REMOVE TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            // Check if its correct
            dap_chain_addr_t *l_add_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            if (dap_chain_addr_check_sum(l_add_addr)) {
                log_it(L_WARNING, "Wrong address checksum in TSD param TX_RECEIVER_ALLOWED_REMOVE");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_ADDR);
            }
            if (!l_new_tx_recv_allow && l_new_tx_recv_allow_size && !l_was_tx_recv_allow_copied) {
                assert(a_item_apply_to->tx_recv_allow);
                // Deep copy addrs to sandbox
                l_new_tx_recv_allow = DAP_DUP_SIZE(a_item_apply_to->tx_recv_allow, l_new_tx_recv_allow_size * sizeof(struct spec_address));
                if (!l_new_tx_recv_allow) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_recv_allow_copied = true;
            // Check if its already present
            size_t i = 0;
            for ( ; i < l_new_tx_recv_allow_size; i++) // Check for all the list
                if (dap_chain_addr_compare(&l_new_tx_recv_allow[i].addr, l_add_addr))
                    break;
            if (i == l_new_tx_recv_allow_size) {
                log_it(L_WARNING, "TSD param TX_RECEIVER_ALLOWED_REMOVE has address %s thats not present in list",
                        dap_chain_addr_to_str_static(l_add_addr));
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
            }
            // Addr removing: swap with last
            size_t l_last_idx = l_new_tx_recv_allow_size - 1;
            if (i < l_last_idx)
                l_new_tx_recv_allow[i] = l_new_tx_recv_allow[l_last_idx];
            l_new_tx_recv_allow_size = l_last_idx;
            // Memory clearing
            if (l_new_tx_recv_allow_size)
                l_new_tx_recv_allow = DAP_REALLOC_COUNT(l_new_tx_recv_allow, l_new_tx_recv_allow_size);
            else
                DAP_DEL_Z(l_new_tx_recv_allow);
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_CLEAR: {
            if (l_tsd->size != 0) {
                log_it(L_WARNING, "Wrong TX_RECEIVER_ALLOWED_CLEAR TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            DAP_DEL_Z(l_new_tx_recv_allow);
            l_new_tx_recv_allow_size = 0;
            l_was_tx_recv_allow_copied = true;
        } break;

        // Blocked tx receiver addres list add, remove or clear
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD: {
            if (l_tsd->size != sizeof(dap_chain_addr_t)) {
                log_it(L_WARNING, "Wrong TX_RECEIVER_BLOCKED_ADD TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            // Check if its correct
            dap_chain_addr_t *l_add_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            if (dap_chain_addr_check_sum(l_add_addr)) {
                log_it(L_WARNING, "Wrong address checksum in TSD param TX_RECEIVER_BLOCKED_ADD");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_ADDR);
            }
            if (!l_new_tx_recv_block && l_new_tx_recv_block_size && !l_was_tx_recv_block_copied) {
                assert(a_item_apply_to->tx_recv_block);
                // Deep copy addrs to sandbox
                l_new_tx_recv_block = DAP_DUP_SIZE(a_item_apply_to->tx_recv_block, l_new_tx_recv_block_size * sizeof(struct spec_address));
                if (!l_new_tx_recv_block) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_recv_block_copied = true;
            // Check if its already present
            for (size_t i = 0; i < l_new_tx_recv_block_size; i++) { // Check for all the list
                if (dap_chain_addr_compare(&l_new_tx_recv_block[i].addr, l_add_addr)) { // Found
                    log_it(L_WARNING, "TSD param TX_RECEIVER_BLOCKED_ADD has address %s thats already present in list",
                                                                    dap_chain_addr_to_str_static(l_add_addr));
                    return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
                }
            }
            struct spec_address *l_tmp = DAP_REALLOC_COUNT_RET_VAL_IF_FAIL(l_new_tx_recv_block, l_new_tx_recv_block_size + 1, m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY));
            l_new_tx_recv_block = l_tmp;
            l_new_tx_recv_block[l_new_tx_recv_block_size++].addr = *l_add_addr;
            l_new_tx_recv_block[l_new_tx_recv_block_size - 1].becomes_effective = dap_time_now();
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_REMOVE: {
            if (l_tsd->size != sizeof(dap_chain_addr_t)) {
                log_it(L_WARNING, "Wrong TX_RECEIVER_BLOCKED_REMOVE TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            // Check if its correct
            dap_chain_addr_t *l_add_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            if (dap_chain_addr_check_sum(l_add_addr)) {
                log_it(L_WARNING, "Wrong address checksum in TSD param TX_RECEIVER_BLOCKED_REMOVE");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_ADDR);
            }
            if (!l_new_tx_recv_block && l_new_tx_recv_block_size && !l_was_tx_recv_block_copied) {
                assert(a_item_apply_to->tx_recv_block);
                // Deep copy addrs to sandbox
                l_new_tx_recv_block = DAP_DUP_SIZE(a_item_apply_to->tx_recv_block, l_new_tx_recv_block_size * sizeof(struct spec_address));
                if (!l_new_tx_recv_block) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_recv_block_copied = true;
            // Check if its already present
            size_t i = 0;
            for ( ; i < l_new_tx_recv_block_size; i++) // Check for all the list
                if (dap_chain_addr_compare(&l_new_tx_recv_block[i].addr, l_add_addr))
                    break;
            if (i == l_new_tx_recv_block_size) {
                log_it(L_WARNING, "TSD param TX_RECEIVER_BLOCKED_REMOVE has address %s thats not present in list",
                        dap_chain_addr_to_str_static(l_add_addr));
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
            }
            // Addr removing: swap with last
            size_t l_last_idx = l_new_tx_recv_block_size - 1;
            if (i < l_last_idx)
                l_new_tx_recv_block[i] = l_new_tx_recv_block[l_last_idx];
            l_new_tx_recv_block_size = l_last_idx;
            // Memory clearing
            if (l_new_tx_recv_block_size)
                l_new_tx_recv_block = DAP_REALLOC(l_new_tx_recv_block,
                                                          l_new_tx_recv_block_size * sizeof(struct spec_address));
            else
                DAP_DEL_Z(l_new_tx_recv_block);
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_CLEAR: {
            if (l_tsd->size != 0) {
                log_it(L_WARNING, "Wrong TX_RECEIVER_BLOCKED_CLEAR TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            DAP_DEL_Z(l_new_tx_recv_block);
            l_new_tx_recv_block_size = 0;
            l_was_tx_recv_block_copied = true;
        } break;

        // Blocked tx sender addres list add, remove or clear
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD: {
            if (l_tsd->size != sizeof(dap_chain_addr_t)) {
                log_it(L_WARNING, "Wrong TX_SENDER_ALLOWED_ADD TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            // Check if its correct
            dap_chain_addr_t *l_add_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            if (dap_chain_addr_check_sum(l_add_addr)) {
                log_it(L_WARNING, "Wrong address checksum in TSD param TX_SENDER_ALLOWED_ADD");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_ADDR);
            }
            if (!l_new_tx_send_allow && l_new_tx_send_allow_size && !l_was_tx_send_allow_copied) {
                assert(a_item_apply_to->tx_send_allow);
                // Deep copy addrs to sandbox
                l_new_tx_send_allow = DAP_DUP_SIZE(a_item_apply_to->tx_send_allow, l_new_tx_send_allow_size * sizeof(struct spec_address));
                if (!l_new_tx_send_allow) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_send_allow_copied = true;
            // Check if its already present
            for (size_t i = 0; i < l_new_tx_send_allow_size; i++) { // Check for all the list
                if (dap_chain_addr_compare(&l_new_tx_send_allow[i].addr, l_add_addr)) { // Found
                    log_it(L_WARNING, "TSD param TX_SENDER_ALLOWED_ADD has address %s thats already present in list",
                                                                    dap_chain_addr_to_str_static(l_add_addr));
                    return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
                }
            }
            struct spec_address *l_tmp = DAP_REALLOC_COUNT_RET_VAL_IF_FAIL(l_new_tx_send_allow, l_new_tx_send_allow_size + 1, m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY));
            l_new_tx_send_allow = l_tmp;
            l_new_tx_send_allow[l_new_tx_send_allow_size++].addr = *l_add_addr;
            l_new_tx_send_allow[l_new_tx_send_allow_size - 1].becomes_effective = dap_time_now();
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_REMOVE: {
            if (l_tsd->size != sizeof(dap_chain_addr_t)) {
                log_it(L_WARNING, "Wrong TX_SENDER_ALLOWED_REMOVE TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            // Check if its correct
            dap_chain_addr_t *l_add_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            if (dap_chain_addr_check_sum(l_add_addr)) {
                log_it(L_WARNING, "Wrong address checksum in TSD param TX_SENDER_ALLOWED_REMOVE");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_ADDR);

            }
            if (!l_new_tx_send_allow && l_new_tx_send_allow_size && !l_was_tx_send_allow_copied) {
                assert(a_item_apply_to->tx_send_allow);
                // Deep copy addrs to sandbox
                l_new_tx_send_allow = DAP_DUP_SIZE(a_item_apply_to->tx_send_allow, l_new_tx_send_allow_size * sizeof(struct spec_address));
                if (!l_new_tx_send_allow) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_send_allow_copied = true;
            // Check if its already present
            size_t i = 0;
            for ( ; i < l_new_tx_send_allow_size; i++) // Check for all the list
                if (dap_chain_addr_compare(&l_new_tx_send_allow[i].addr, l_add_addr))
                    break;
            if (i == l_new_tx_send_allow_size) {
                log_it(L_WARNING, "TSD param TX_SENDER_ALLOWED_REMOVE has address %s thats not present in list",
                        dap_chain_addr_to_str_static(l_add_addr));
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
            }
            // Addr removing: swap with last
            size_t l_last_idx = l_new_tx_send_allow_size - 1;
            if (i < l_last_idx)
                l_new_tx_send_allow[i] = l_new_tx_send_allow[l_last_idx];
            l_new_tx_send_allow_size = l_last_idx;
            // Memory clearing
            if (l_new_tx_send_allow_size)
                l_new_tx_send_allow = DAP_REALLOC(l_new_tx_send_allow,
                                                          l_new_tx_send_allow_size * sizeof(struct spec_address));
            else
                DAP_DEL_Z(l_new_tx_send_allow);
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_CLEAR: {
            if (l_tsd->size != 0) {
                log_it(L_WARNING, "Wrong TX_SENDER_ALLOWED_CLEAR TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            DAP_DEL_Z(l_new_tx_send_allow);
            l_new_tx_send_allow_size = 0;
            l_was_tx_send_allow_copied = true;
        } break;

        // Blocked tx sender addres list add, remove or clear
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD: {
            if (l_tsd->size != sizeof(dap_chain_addr_t)) {
                log_it(L_WARNING, "Wrong TX_SENDER_BLOCKED_ADD TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            // Check if its correct
            dap_chain_addr_t *l_add_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            if (dap_chain_addr_check_sum(l_add_addr)) {
                log_it(L_WARNING, "Wrong address checksum in TSD param TX_SENDER_BLOCKED_ADD");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_ADDR);
            }
            if (!l_new_tx_send_block && l_new_tx_send_block_size && !l_was_tx_send_block_copied) {
                assert(a_item_apply_to->tx_send_block);
                // Deep copy addrs to sandbox
                l_new_tx_send_block = DAP_DUP_SIZE(a_item_apply_to->tx_send_block, l_new_tx_send_block_size * sizeof(struct spec_address));
                if (!l_new_tx_send_block) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_send_block_copied = true;
            // Check if its already present
            for (size_t i = 0; i < l_new_tx_send_block_size; i++) { // Check for all the list
                if (dap_chain_addr_compare(&l_new_tx_send_block[i].addr, l_add_addr)) { // Found
                    log_it(L_WARNING, "TSD param TX_SENDER_BLOCKED_ADD has address %s thats already present in list",
                                                                    dap_chain_addr_to_str_static(l_add_addr));
                    return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
                }
            }
            if (!a_apply)
                break;
            struct spec_address *l_tmp = DAP_REALLOC_COUNT_RET_VAL_IF_FAIL(l_new_tx_send_block, l_new_tx_send_block_size + 1, m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY));
            l_new_tx_send_block = l_tmp;
            l_new_tx_send_block[l_new_tx_send_block_size++].addr = *l_add_addr;
            l_new_tx_send_block[l_new_tx_send_block_size - 1].becomes_effective = dap_time_now();
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_REMOVE: {
            if (l_tsd->size != sizeof(dap_chain_addr_t)) {
                log_it(L_WARNING, "Wrong TX_SENDER_BLOCKED_REMOVE TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            // Check if its correct
            dap_chain_addr_t *l_add_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            if (dap_chain_addr_check_sum(l_add_addr)) {
                log_it(L_WARNING, "Wrong address checksum in TSD param TX_SENDER_BLOCKED_REMOVE");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_ADDR);
            }
            if (!l_new_tx_send_block && l_new_tx_send_block_size && !l_was_tx_send_block_copied) {
                assert(a_item_apply_to->tx_send_block);
                // Deep copy addrs to sandbox
                l_new_tx_send_block = DAP_DUP_SIZE(a_item_apply_to->tx_send_block, l_new_tx_send_block_size * sizeof(struct spec_address));
                if (!l_new_tx_send_block) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_send_block_copied = true;
            // Check if its already present
            size_t i = 0;
            for ( ; i < l_new_tx_send_block_size; i++) // Check for all the list
                if (dap_chain_addr_compare(&l_new_tx_send_block[i].addr, l_add_addr))
                    break;
            if (i == l_new_tx_send_block_size) {
                log_it(L_WARNING, "TSD param TX_SENDER_BLOCKED_REMOVE has address %s thats not present in list",
                        dap_chain_addr_to_str_static(l_add_addr));
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
            }
            // Addr removing: swap with last
            size_t l_last_idx = l_new_tx_send_block_size - 1;
            if (i < l_last_idx)
                l_new_tx_send_block[i] = l_new_tx_send_block[l_last_idx];
            l_new_tx_send_block_size = l_last_idx;
            // Memory clearing
            if (l_new_tx_send_block_size)
                l_new_tx_send_block = DAP_REALLOC_COUNT(l_new_tx_send_block, l_new_tx_send_block_size);
            else
                DAP_DEL_Z(l_new_tx_send_block);
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_CLEAR: {
            if (l_tsd->size != 0) {
                log_it(L_WARNING, "Wrong TX_SENDER_BLOCKED_CLEAR TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            DAP_DEL_Z(l_new_tx_send_block);
            l_new_tx_send_block_size = 0;
            l_was_tx_send_block_copied = true;
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TOKEN_DESCRIPTION: {
            if (l_tsd->size == 0 || l_tsd->data[l_tsd->size - 1] != 0) {
                log_it(L_ERROR, "Wrong TOKEN_DESCRIPTION TSD format or size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            if (!a_apply)
                break;
            DAP_DEL_Z(a_item_apply_to->description);
            a_item_apply_to->description = strdup((char *)l_tsd->data);
        } break;

        // Set signs count value need to emission be valid
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID: {
            if (l_tsd->size != sizeof(uint16_t)) {
                log_it(L_WARNING, "Wrong SIGNS_VALID TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            l_new_signs_valid = dap_tsd_get_scalar(l_tsd, uint16_t);
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_ADD: {
            if (l_tsd->size < sizeof(dap_pkey_t) || l_tsd->size != dap_pkey_get_size((dap_pkey_t *)l_tsd->data)) {
                log_it(L_WARNING, "Wrong TOTAL_PKEYS_ADD TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            if (!l_new_pkeys && l_new_signs_total && !l_was_pkeys_copied) {
                assert(a_item_apply_to->auth_pkeys);
                assert(a_item_apply_to->auth_pkey_hashes);
                // Deep copy pkeys & its hashes to sandbox
                l_new_pkeys = DAP_NEW_SIZE(dap_pkey_t *, l_new_signs_total * sizeof(dap_pkey_t *));
                if (!l_new_pkeys) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
                for (size_t i = 0; i < l_new_signs_total; i++) {
                    l_new_pkeys[i] = DAP_DUP_SIZE(a_item_apply_to->auth_pkeys[i], dap_pkey_get_size(a_item_apply_to->auth_pkeys[i]));
                    if (!l_new_pkeys[i]) {
                        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                        return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                    }
                }
                assert(!l_new_pkey_hashes);
                l_new_pkey_hashes = DAP_DUP_SIZE(a_item_apply_to->auth_pkey_hashes, l_new_signs_total * sizeof(dap_hash_t));
                if (!l_new_pkey_hashes) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_pkeys_copied = true;
            dap_pkey_t *l_new_auth_pkey = dap_tsd_get_object(l_tsd, dap_pkey_t);
            dap_pkey_type_t l_pkey_type_correction = { .type = DAP_PKEY_TYPE_NULL };
            if (dap_pkey_type_to_enc_key_type(l_new_auth_pkey->header.type) == DAP_ENC_KEY_TYPE_INVALID) {
                dap_sign_type_t l_sign_type = { .type = l_new_auth_pkey->header.type.type }; // Legacy cratch
                l_pkey_type_correction = dap_pkey_type_from_sign_type(l_sign_type);
                if (l_pkey_type_correction.type == DAP_PKEY_TYPE_NULL) {
                    log_it(L_WARNING, "Unknonw public key type %hu", l_new_auth_pkey->header.type.type);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_PARSE_ERROR);
                }
            }
            // Check if its already present
            dap_hash_t l_new_auth_pkey_hash;
            dap_pkey_get_hash(l_new_auth_pkey, &l_new_auth_pkey_hash);
            for (size_t i = 0; i < l_new_signs_total; i++) {
                if (dap_pkey_compare(l_new_auth_pkey, l_new_pkeys[i])) {
                    log_it(L_WARNING, "TSD param TOTAL_PKEYS_ADD has pkey %s thats already present in list",
                                                                    dap_hash_fast_to_str_static(&l_new_auth_pkey_hash));
                    return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_PKEY_MISMATCH);
                }
            }
            dap_pkey_t **l_tmp = DAP_REALLOC_COUNT_RET_VAL_IF_FAIL(l_new_pkeys, l_new_signs_total + 1, m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY));
            l_new_pkeys = l_tmp;
            // Pkey adding
            l_new_pkeys[l_new_signs_total] = DAP_DUP_SIZE(l_new_auth_pkey, dap_pkey_get_size(l_new_auth_pkey));
            if (!l_new_pkeys[l_new_signs_total]) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
            }
            if (l_pkey_type_correction.type != DAP_PKEY_TYPE_NULL)
                l_new_pkeys[l_new_signs_total]->header.type = l_pkey_type_correction;

            dap_hash_fast_t *l_tmp_hashes = DAP_REALLOC_COUNT_RET_VAL_IF_FAIL(l_new_pkey_hashes, l_new_signs_total + 1, m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY));
            l_new_pkey_hashes = l_tmp_hashes;
            l_new_pkey_hashes[l_new_signs_total++] = l_new_auth_pkey_hash;
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_REMOVE: {
            if (l_tsd->size != sizeof(dap_hash_t)) {
                log_it(L_WARNING, "Wrong TOTAL_PKEYS_REMOVE TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            if (!l_new_pkeys && l_new_signs_total && !l_was_pkeys_copied) {
                assert(a_item_apply_to->auth_pkeys);
                assert(a_item_apply_to->auth_pkey_hashes);
                // Deep copy pkeys & its hashes to sandbox
                l_new_pkeys = DAP_NEW_SIZE(dap_pkey_t *, l_new_signs_total * sizeof(dap_pkey_t *));
                if (!l_new_pkeys) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
                for (size_t i = 0; i < l_new_signs_total; i++) {
                    l_new_pkeys[i] = DAP_DUP_SIZE(a_item_apply_to->auth_pkeys[i], dap_pkey_get_size(a_item_apply_to->auth_pkeys[i]));
                    if (!l_new_pkeys[i]) {
                        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                        return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                    }
                }
                assert(!l_new_pkey_hashes);
                l_new_pkey_hashes = DAP_DUP_SIZE(a_item_apply_to->auth_pkey_hashes, l_new_signs_total * sizeof(dap_hash_t));
                if (!l_new_pkey_hashes) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_pkeys_copied = true;
            dap_hash_t l_new_auth_pkey_hash = dap_tsd_get_scalar(l_tsd, dap_hash_t);
            // Check if its already present
            size_t i = 0;
            for ( ; i < l_new_signs_total; i++) // Check for all the list
                if (dap_hash_fast_compare(l_new_pkey_hashes + i, &l_new_auth_pkey_hash))
                    break;
            if (i == l_new_signs_total) {
                log_it(L_WARNING, "TSD param TOTAL_PKEYS_REMOVE has public key hash %s thats not present in list",
                                                    dap_hash_fast_to_str_static(&l_new_auth_pkey_hash));
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_PKEY_MISMATCH);
            }
            // Pkey removing: swap with last to avoid O(n) shifts
            size_t l_last_idx = l_new_signs_total - 1;
            DAP_DEL_Z(l_new_pkeys[i]);
            if (i < l_last_idx) {
                l_new_pkeys[i] = l_new_pkeys[l_last_idx];
                l_new_pkey_hashes[i] = l_new_pkey_hashes[l_last_idx];
            }
            l_new_signs_total = l_last_idx;
            // Memory clearing
            if (l_new_signs_total) {
                l_new_pkeys = DAP_REALLOC_COUNT(l_new_pkeys, l_new_signs_total);
                l_new_pkey_hashes = DAP_REALLOC_COUNT(l_new_pkey_hashes, l_new_signs_total);
            } else
                DAP_DEL_MULTY(l_new_pkeys, l_new_pkey_hashes);
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK: {
            if (a_current_datum->subtype != DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE) {
                log_it(L_WARNING, "TSD section DELEGATE_EMISSION_FROM_STAKE_LOCK allowed for NATIVE subtype only");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_FORBIDDEN);
            }
            if (l_tsd->size != sizeof(dap_chain_datum_token_tsd_delegate_from_stake_lock_t) &&
                    l_tsd->size != sizeof(dap_chain_datum_token_tsd_delegate_from_stake_lock_t) + 256 /* Legacy size */) {
                log_it(L_WARNING, "Wrong DELEGATE_EMISSION_FROM_STAKE_LOCK TSD size %" DAP_UINT64_FORMAT_U ", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            dap_chain_datum_token_tsd_delegate_from_stake_lock_t *l_delegate = dap_tsd_get_object(l_tsd, dap_chain_datum_token_tsd_delegate_from_stake_lock_t);
            const char *l_basic_token_ticker = (const char *)l_delegate->ticker_token_from;
            char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
            dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, l_basic_token_ticker);
            if (dap_strcmp(l_delegated_ticker, a_current_datum->ticker)) {
                log_it(L_WARNING, "Unexpected delegated token ticker %s (expected %s)", a_current_datum->ticker, l_delegated_ticker);
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_OTHER_TICKER_EXPECTED);
            }
            dap_ledger_token_item_t *l_basic_token = NULL;
            HASH_FIND_STR(PVT(a_ledger)->tokens, l_basic_token_ticker, l_basic_token);
            if (!l_basic_token) {
                log_it(L_WARNING, "Basic token ticker %s for delegated token isn't found", l_basic_token_ticker);
                return m_ret_cleanup(DAP_LEDGER_CHECK_TICKER_NOT_FOUND);
            }
            if (IS_ZERO_256(l_delegate->emission_rate)) {
                log_it(L_WARNING, "Emission rate for delegated toke should not be a zero");
                return m_ret_cleanup(DAP_LEDGER_CHECK_ZERO_VALUE);
            }
            if (!a_apply)
                break;
            assert(a_item_apply_to);
            a_item_apply_to->is_delegated = true;
            dap_strncpy(a_item_apply_to->delegated_from, l_basic_token->ticker, sizeof(a_item_apply_to->delegated_from));
            a_item_apply_to->emission_rate = l_delegate->emission_rate;
        } break;

        default:
            log_it(L_ERROR, "Unexpected TSD type %hu", l_tsd->type);
            return m_ret_cleanup(DAP_LEDGER_CHECK_PARSE_ERROR);
        }
    }
    if (l_new_signs_total < l_new_signs_valid)
        return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS);

    if (!a_apply)
        return m_ret_cleanup(DAP_LEDGER_CHECK_OK);
#undef m_ret_cleanup

    if (l_was_tx_recv_allow_copied) {
        a_item_apply_to->tx_recv_allow_size = l_new_tx_recv_allow_size;
        DAP_DEL_Z(a_item_apply_to->tx_recv_allow);
        a_item_apply_to->tx_recv_allow = l_new_tx_recv_allow;
    }
    if (l_was_tx_recv_block_copied) {
        a_item_apply_to->tx_recv_block_size = l_new_tx_recv_block_size;
        DAP_DEL_Z(a_item_apply_to->tx_recv_block);
        a_item_apply_to->tx_recv_block = l_new_tx_recv_block;
    }
    if (l_was_tx_send_allow_copied) {
        a_item_apply_to->tx_send_allow_size = l_new_tx_send_allow_size;
        DAP_DEL_Z(a_item_apply_to->tx_send_allow);
        a_item_apply_to->tx_send_allow = l_new_tx_send_allow;
    }
    if (l_was_tx_send_block_copied) {
        a_item_apply_to->tx_send_block_size = l_new_tx_send_block_size;
        DAP_DEL_Z(a_item_apply_to->tx_send_block);
        a_item_apply_to->tx_send_block = l_new_tx_send_block;
    }
    a_item_apply_to->auth_signs_valid = l_new_signs_valid;
    if (l_was_pkeys_copied) {
        for (size_t i = 0; i < a_item_apply_to->auth_signs_total; i++)
            DAP_DELETE(a_item_apply_to->auth_pkeys[i]);
        DAP_DEL_Z(a_item_apply_to->auth_pkeys);
        DAP_DEL_Z(a_item_apply_to->auth_pkey_hashes);
        a_item_apply_to->auth_signs_total = l_new_signs_total;
        a_item_apply_to->auth_pkeys = l_new_pkeys;
        a_item_apply_to->auth_pkey_hashes = l_new_pkey_hashes;
    }
    return DAP_LEDGER_CHECK_OK;
}

/**
 * @brief dap_ledger_token_check
 * @param a_ledger
 * @param a_token
 * @param a_token_size
 * @return
 */
int s_token_add_check(dap_ledger_t *a_ledger, byte_t *a_token, size_t a_token_size,
                      dap_ledger_token_item_t **a_token_item, dap_chain_datum_token_t **a_token_out,
                      size_t *a_tsd_total_size, size_t *a_signs_size,
                      dap_hash_fast_t *a_token_update_hash)
{
    size_t l_token_size = a_token_size;
    dap_chain_datum_token_t *l_token = dap_chain_datum_token_read(a_token, &l_token_size);
    if (!l_token)
        return DAP_LEDGER_CHECK_INVALID_SIZE;
    if (!dap_chain_datum_token_check_ticker(l_token->ticker)) {
        log_it(L_WARNING, "Token ticker %*s isn't a valid one", DAP_CHAIN_TICKER_SIZE_MAX, l_token->ticker);
        DAP_DELETE(l_token);
        return DAP_LEDGER_CHECK_INVALID_TICKER;
    }
    bool l_legacy_type = a_token_size != l_token_size;
    if (l_legacy_type && !a_token_item) { // It's mempool check
        log_it(L_WARNING, "Legacy token type %hu isn't supported for a new declaration", l_token->type);
        DAP_DELETE(l_token);
        return DAP_LEDGER_TOKEN_ADD_CHECK_LEGACY_FORBIDDEN;
    }
    if (l_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE && l_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_DECL) {
        log_it(L_WARNING, "Unknown token type %hu", l_token->type);
        DAP_DELETE(l_token);
        return DAP_LEDGER_CHECK_PARSE_ERROR;
    }
    if (!l_token->ticker[0] || l_token->ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1]) {
        log_it(L_WARNING, "Unreadable token ticker");
        DAP_DELETE(l_token);
        return DAP_LEDGER_CHECK_PARSE_ERROR;
    }
    char *ptr = l_token->ticker;
    while (*ptr) {
        if (!dap_ascii_isalnum(*ptr++)) {
            log_it(L_WARNING, "Token ticker is not alpha-numeric");
            DAP_DELETE(l_token);
            return DAP_LEDGER_CHECK_PARSE_ERROR;
        }
    }
    if (!l_token->signs_total) {
        log_it(L_WARNING, "No auth signs in token '%s' datum!", l_token->ticker);
        DAP_DELETE(l_token);
        return DAP_LEDGER_TOKEN_ADD_CHECK_NOT_ENOUGH_UNIQUE_SIGNS;
    }
    bool l_update_token = l_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    dap_ledger_token_item_t *l_token_item = dap_ledger_pvt_find_token(a_ledger, l_token->ticker);
    dap_hash_fast_t l_token_update_hash = {};
    if (l_token_item) {
        if (!l_update_token) {
            log_it(L_WARNING, "Duplicate token declaration for ticker '%s'", l_token->ticker);
            DAP_DELETE(l_token);
            return DAP_LEDGER_CHECK_ALREADY_CACHED;
        }
        if (l_token->signs_total < l_token_item->auth_signs_valid) {
            log_it(L_WARNING, "Datum token for ticker '%s' has only %hu signatures out of %zu",
                                            l_token->ticker, l_token->signs_total, l_token_item->auth_signs_valid);
            DAP_DELETE(l_token);
            return DAP_LEDGER_TOKEN_ADD_CHECK_NOT_ENOUGH_UNIQUE_SIGNS;
        }
        dap_hash_fast(l_token, l_token_size, &l_token_update_hash);
        dap_ledger_token_update_item_t *l_token_update_item = NULL;
        pthread_rwlock_rdlock(&l_token_item->token_ts_updated_rwlock);
        HASH_FIND(hh, l_token_item->token_ts_updated, &l_token_update_hash, sizeof(dap_hash_fast_t), l_token_update_item);
        pthread_rwlock_unlock(&l_token_item->token_ts_updated_rwlock);
        if (l_token_update_item) {
            log_it(L_WARNING, "This update for token '%s' was already applied", l_token->ticker);
            DAP_DELETE(l_token);
            return DAP_LEDGER_CHECK_ALREADY_CACHED;
        }
        if (a_token_update_hash)
            *a_token_update_hash = l_token_update_hash;
    } else if (l_update_token) {
        log_it(L_WARNING, "Can't update token that doesn't exist for ticker '%s'", l_token->ticker);
        DAP_DELETE(l_token);
        return DAP_LEDGER_CHECK_TICKER_NOT_FOUND;
    } else if (l_token->signs_total < l_token->signs_valid) {
        log_it(L_WARNING, "Datum token for ticker '%s' has only %hu signatures out of %hu",
                                            l_token->ticker, l_token->signs_total, l_token->signs_valid);
        DAP_DELETE(l_token);
        return DAP_LEDGER_TOKEN_ADD_CHECK_NOT_ENOUGH_UNIQUE_SIGNS;
    }
    // Check TSD
    size_t l_size_tsd_section = 0;
    if (l_update_token) {
        switch (l_token->subtype) {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
            l_size_tsd_section = l_token->header_private_decl.tsd_total_size; break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
            l_size_tsd_section = l_token->header_native_decl.tsd_total_size; break;
        default:
            /* Bogdanoff, unknown token subtype update. What shall we TODO? */
            log_it(L_WARNING, "Unsupported token subtype '0x%0hX' update! "
                              "Ticker: %s, total_supply: %s, signs_valid: %hu, signs_total: %hu",
                              l_token->type, l_token->ticker, dap_uint256_to_char(l_token->total_supply, NULL),
                              l_token->signs_valid, l_token->signs_total);
            /* Dump it right now */
            DAP_DELETE(l_token);
            return DAP_LEDGER_CHECK_PARSE_ERROR;
        }
    } else {
        switch (l_token->subtype) {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
            l_size_tsd_section = l_token->header_private_update.tsd_total_size; break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
            l_size_tsd_section = l_token->header_native_update.tsd_total_size; break;
        default:
            /* Bogdanoff, unknown token subtype declaration. What shall we TODO? */
            log_it(L_WARNING, "Unsupported token subtype '0x%0hX' declaration! "
                              "Ticker: %s, total_supply: %s, signs_valid: %hu, signs_total: %hu",
                              l_token->type, l_token->ticker, dap_uint256_to_char(l_token->total_supply, NULL),
                              l_token->signs_valid, l_token->signs_total);
            /* Dump it right now */
            DAP_DELETE(l_token);
            return DAP_LEDGER_CHECK_PARSE_ERROR;
        }
    }
    if (sizeof(dap_chain_datum_token_t) + l_size_tsd_section > l_token_size ||
            sizeof(dap_chain_datum_token_t) + l_size_tsd_section < l_size_tsd_section) {
        log_it(L_WARNING, "Incorrect size %zu of datum token, expected at least %zu", l_token_size,
                                                sizeof(dap_chain_datum_token_t) + l_size_tsd_section);
        DAP_DELETE(l_token);
        return DAP_LEDGER_CHECK_INVALID_SIZE;
    }
    // Check signs
    byte_t *l_signs_ptr = l_token->tsd_n_signs + l_size_tsd_section;
    uint64_t l_signs_size = 0, l_signs_offset = sizeof(dap_chain_datum_token_t) + l_size_tsd_section;
    for (uint16_t l_signs_passed = 0; l_signs_passed < l_token->signs_total; l_signs_passed++) {
        dap_sign_t *l_sign = (dap_sign_t *)(l_signs_ptr + l_signs_size);
        if (l_signs_offset + l_signs_size + sizeof(dap_sign_t) > l_token_size ||
                l_signs_offset + l_signs_size + sizeof(dap_sign_t) < l_signs_offset) {
            log_it(L_WARNING, "Incorrect size %zu of datum token, expected at least %zu", l_token_size,
                                                    l_signs_offset + l_signs_size + sizeof(dap_sign_t));
            DAP_DELETE(l_token);
            return DAP_LEDGER_CHECK_INVALID_SIZE;
        }
        uint64_t l_sign_size = dap_sign_get_size(l_sign);
        if (!l_sign_size || l_sign_size + l_signs_size < l_signs_size) {
            log_it(L_WARNING, "Incorrect size %zu of datum token sign", l_sign_size);
            DAP_DELETE(l_token);
            return DAP_LEDGER_CHECK_INVALID_SIZE;
        }
        l_signs_size += l_sign_size;
    }
    if (l_token_size != l_signs_offset + l_signs_size) {
        log_it(L_WARNING, "Incorrect size %zu of datum token, expected %zu", l_token_size, l_signs_offset + l_signs_size);
        DAP_DELETE(l_token);
        return DAP_LEDGER_CHECK_INVALID_SIZE;
    }
    size_t l_signs_unique = l_token->signs_total;
    dap_sign_t **l_signs = dap_sign_get_unique_signs(l_signs_ptr, l_signs_size, &l_signs_unique);
    if (l_signs_unique != l_token->signs_total) {
        DAP_DEL_Z(l_signs);
        log_it(L_WARNING, "The number of unique token signs %zu is less than total token signs set to %hu",
               l_signs_unique, l_token->signs_total);
        DAP_DELETE(l_token);
        return DAP_LEDGER_TOKEN_ADD_CHECK_NOT_ENOUGH_UNIQUE_SIGNS;
    }
    size_t l_signs_approve = 0;
    size_t l_verify_size = 0;
    uint16_t l_tmp_auth_signs = 0;
    if (l_legacy_type)
        l_verify_size = sizeof(dap_chain_datum_token_old_t) - sizeof(uint16_t);
    else {
        l_verify_size = l_signs_offset;
        l_tmp_auth_signs = l_token->signs_total;
        l_token->signs_total = 0;
    }
    for (size_t i = 0; i < l_signs_unique; i++) {
        if (!dap_sign_verify(l_signs[i], l_legacy_type ? a_token : (void *)l_token, l_verify_size)) {
            if (l_update_token) {
                for (size_t j = 0; j < l_token_item->auth_signs_total; j++) {
                    if (dap_pkey_compare_with_sign(l_token_item->auth_pkeys[j], l_signs[i])) {
                        l_signs_approve++;
                        break;
                    }
                }
            } else
                l_signs_approve++;
        }
    }
    DAP_DELETE(l_signs);
    if (!l_legacy_type)
        l_token->signs_total = l_tmp_auth_signs;
    size_t l_signs_need = l_update_token ? l_token_item->auth_signs_valid : l_token->signs_total;
    if (l_signs_approve < l_signs_need) {
        log_it(L_WARNING, "Datum token for ticker '%s' has only %zu valid signatures out of %zu",
                                                l_token->ticker, l_signs_approve, l_signs_need);
        DAP_DELETE(l_token);
        return DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS;
    }
    // Check content & size of enclosed TSD sections
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    int ret = s_token_tsd_parse(l_token_item, l_token, a_ledger, l_token->tsd_n_signs, l_size_tsd_section, false);
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    bool l_is_whitelisted = false;
    if (ret != DAP_LEDGER_CHECK_OK) {
        dap_hash_fast_t l_token_hash;
        if (!dap_hash_fast_is_blank(&l_token_update_hash))
            l_token_hash = l_token_update_hash;
        else
            dap_hash_fast(a_token, a_token_size, &l_token_hash);
            
        if (!( l_is_whitelisted = dap_ledger_datum_is_enforced(a_ledger, &l_token_hash, true) )) {
            DAP_DELETE(l_token);
            return ret;
        }
    }
    if (a_token_item)
        *a_token_item = l_token_item;
    if (a_token_out)
        *a_token_out = l_token;
    else
        DAP_DELETE(l_token);
    if (a_tsd_total_size)
        *a_tsd_total_size = l_size_tsd_section;
    if (a_signs_size)
        *a_signs_size = l_signs_size;
    return l_is_whitelisted ? DAP_LEDGER_CHECK_WHITELISTED : DAP_LEDGER_CHECK_OK;
}

int dap_ledger_token_add_check(dap_ledger_t *a_ledger, byte_t *a_token, size_t a_token_size)
{
    dap_return_val_if_fail(a_ledger && a_token && a_token_size, DAP_LEDGER_CHECK_INVALID_ARGS);
    int ret = s_token_add_check(a_ledger, a_token, a_token_size, NULL, NULL, NULL, NULL, NULL);
    if (ret == DAP_LEDGER_CHECK_WHITELISTED)
        ret = DAP_LEDGER_CHECK_OK;
    return ret;
}

/**
 * @brief dap_ledger_token_ticker_check
 * @param a_ledger
 * @param a_token_ticker
 * @return
 */
dap_chain_datum_token_t *dap_ledger_token_ticker_check(dap_ledger_t *a_ledger, const char *a_token_ticker)
{
    dap_return_val_if_fail(a_ledger && a_token_ticker, NULL);
    dap_ledger_token_item_t *l_token_item = dap_ledger_pvt_find_token(a_ledger, a_token_ticker);
    return l_token_item ? l_token_item->datum_token : NULL;
}

/**
 * @brief update current_supply in token cache
 *
 * @param a_ledger ledger object
 * @param l_token_item token item object
 */
void s_ledger_token_cache_update(dap_ledger_t *a_ledger, dap_ledger_token_item_t *l_token_item)
{
    if (! is_ledger_cached(PVT(a_ledger)) )
        return;
    char *l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_TOKENS_STR);
    size_t l_cache_size = l_token_item->datum_token_size + sizeof(uint256_t);
    uint8_t *l_cache = DAP_NEW_STACK_SIZE(uint8_t, l_cache_size);
    if ( !l_cache ) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return;
    }
    memcpy(l_cache, &l_token_item->current_supply, sizeof(uint256_t));
    memcpy(l_cache + sizeof(uint256_t), l_token_item->datum_token, l_token_item->datum_token_size);
    if (dap_global_db_set(l_gdb_group, l_token_item->ticker, l_cache, l_cache_size, false, NULL, NULL)) {
        char *l_supply = dap_chain_balance_datoshi_print(l_token_item->current_supply);
        log_it(L_WARNING, "Ledger cache mismatch, can't add token [%s] with supply %s", l_token_item->ticker, l_supply);
        DAP_DELETE(l_supply);
    }
    DAP_DELETE(l_gdb_group);
}

bool dap_ledger_pvt_token_supply_check(dap_ledger_token_item_t *a_token_item, uint256_t a_value)
{
    if ((IS_ZERO_256(a_token_item->total_supply) || IS_ZERO_256(a_value)))
        return true;
    if (compare256(a_token_item->current_supply, a_value) >= 0)
        return true;
    char *l_supply_str = dap_chain_balance_datoshi_print(a_token_item->current_supply);
    char *l_value_str = dap_chain_balance_datoshi_print(a_value);
    log_it(L_WARNING, "Token current supply %s < emission value %s", l_supply_str, l_value_str);
    DAP_DEL_MULTY(l_supply_str, l_value_str);
    return false;
}

bool dap_ledger_pvt_token_supply_check_update(dap_ledger_t *a_ledger, dap_ledger_token_item_t *a_token_item, uint256_t a_value, bool a_for_removing)
{
    assert(a_token_item);
    if ((IS_ZERO_256(a_token_item->total_supply) || IS_ZERO_256(a_value)))
        return true;
    if (!dap_ledger_pvt_token_supply_check(a_token_item, a_value) && !a_for_removing)
        return false;
    int l_overflow = a_for_removing
        ? SUM_256_256(a_token_item->current_supply, a_value, &a_token_item->current_supply)
        : SUBTRACT_256_256(a_token_item->current_supply, a_value, &a_token_item->current_supply);
    assert(!l_overflow);
    const char *l_balance; dap_uint256_to_char(a_token_item->current_supply, &l_balance);
    log_it(L_NOTICE, "New current supply %s for token %s", l_balance, a_token_item->ticker);
    s_ledger_token_cache_update(a_ledger, a_token_item);
    return true;
}

/**
 * @brief dap_ledger_token_add
 * @param a_ledger Ledger object
 * @param a_token Token datum bytes
 * @param a_token_size Token datum size
 * @param a_creation_time Token creation time (used for address effective time)
 * @return Error code or DAP_LEDGER_CHECK_OK
 */
int dap_ledger_token_add(dap_ledger_t *a_ledger, byte_t *a_token, size_t a_token_size, dap_time_t a_creation_time)
{
    dap_return_val_if_fail(a_ledger && a_token && a_token_size, DAP_LEDGER_CHECK_INVALID_ARGS);
    dap_ledger_token_item_t *l_token_item = NULL;
    dap_chain_datum_token_t *l_token = NULL;
    size_t l_tsd_total_size = 0, l_signs_size = 0;
    dap_hash_fast_t l_token_update_hash;
    int ret = s_token_add_check(a_ledger, a_token, a_token_size, &l_token_item, &l_token,
                                &l_tsd_total_size, &l_signs_size, &l_token_update_hash);
    if (ret != DAP_LEDGER_CHECK_OK && ret != DAP_LEDGER_CHECK_WHITELISTED)
        return ret;

    if (!l_token_item) {
        assert(l_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_DECL);
        l_token_item = DAP_NEW_Z(dap_ledger_token_item_t);
        if ( !l_token_item ) {
            DAP_DELETE(l_token);
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
        }
        *l_token_item = (dap_ledger_token_item_t) {
                .subtype            = l_token->subtype,
                .total_supply       = l_token->total_supply,
                .current_supply     = l_token->total_supply,
                .auth_signs_total   = l_token->signs_total,
                .auth_signs_valid   = l_token->signs_valid,
                .token_emissions_rwlock     = PTHREAD_RWLOCK_INITIALIZER,
                .token_ts_updated_rwlock    = PTHREAD_RWLOCK_INITIALIZER,
                .auth_pkeys         = DAP_NEW_Z_SIZE(dap_pkey_t*, sizeof(dap_pkey_t*) * l_token->signs_total),
                .auth_pkey_hashes   = DAP_NEW_Z_SIZE(dap_chain_hash_fast_t, sizeof(dap_chain_hash_fast_t) * l_token->signs_total),
                .flags = 0
        };
        switch (l_token->subtype) {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
            l_token_item->flags = l_token->header_private_decl.flags; break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
            l_token_item->flags = l_token->header_native_decl.flags; break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC:
            l_token_item->flags = l_token->header_public.flags; break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE:
        default:;
        }
        if ( !l_token_item->auth_pkeys ) {
            DAP_DEL_MULTY(l_token, l_token_item);
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
        };
        if ( !l_token_item->auth_pkey_hashes ) {
            DAP_DEL_MULTY(l_token, l_token_item->auth_pkeys, l_token_item);
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
        }
        size_t l_auth_signs_total = l_token->signs_total;
        dap_sign_t **l_signs = dap_sign_get_unique_signs(l_token->tsd_n_signs + l_tsd_total_size,
                                                         l_signs_size,
                                                         &l_auth_signs_total);
#define CLEAN_UP DAP_DEL_MULTY(l_token, l_token_item->auth_pkeys, l_token_item->auth_pkey_hashes, l_token_item)
        if (!l_signs) {
            CLEAN_UP;
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
        }
        dap_stpcpy((char *)l_token_item->ticker, l_token->ticker);
        for (uint16_t k = 0; k < l_token_item->auth_signs_total; k++) {
            l_token_item->auth_pkeys[k] = dap_pkey_get_from_sign(l_signs[k]);
            if (!l_token_item->auth_pkeys[k]) {
                CLEAN_UP;
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
            }
            dap_pkey_get_hash(l_token_item->auth_pkeys[k], &l_token_item->auth_pkey_hashes[k]);
        }
#undef CLEAN_UP
        DAP_DELETE(l_signs);
        l_token_item->datum_token_size = sizeof(dap_chain_datum_token_t) + l_tsd_total_size + l_signs_size;
        l_token_item->datum_token = l_token;
        pthread_rwlock_wrlock(&PVT(a_ledger)->tokens_rwlock);
        HASH_ADD_STR(PVT(a_ledger)->tokens, ticker, l_token_item);
    } else {
        assert(l_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE);
        pthread_rwlock_wrlock(&PVT(a_ledger)->tokens_rwlock);
        dap_ledger_token_update_item_t *l_token_update_item = NULL;
        pthread_rwlock_wrlock(&l_token_item->token_ts_updated_rwlock);
        HASH_FIND(hh, l_token_item->token_ts_updated, &l_token_update_hash, sizeof(dap_hash_fast_t), l_token_update_item);
        if (l_token_update_item) {
            pthread_rwlock_unlock(&l_token_item->token_ts_updated_rwlock);
            pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
            log_it(L_ERROR, "Token update with hash %s already exist in token %s hash-table",
                            dap_hash_fast_to_str_static(&l_token_update_hash), l_token->ticker);
            DAP_DELETE(l_token);
            return DAP_LEDGER_CHECK_APPLY_ERROR;
        }
        l_token_update_item = DAP_NEW(dap_ledger_token_update_item_t);
        if (!l_token_update_item) {
            pthread_rwlock_unlock(&l_token_item->token_ts_updated_rwlock);
            pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            DAP_DELETE(l_token);
            return DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
        }
        *l_token_update_item = (dap_ledger_token_update_item_t) {
                .update_token_hash			= l_token_update_hash,
                .datum_token_update			= l_token,
                .datum_token_update_size	= sizeof(dap_chain_datum_token_t) + l_tsd_total_size + l_signs_size,
                .updated_time               = dap_time_now()
        };
        HASH_ADD(hh, l_token_item->token_ts_updated, update_token_hash, sizeof(dap_chain_hash_fast_t), l_token_update_item);
        pthread_rwlock_unlock(&l_token_item->token_ts_updated_rwlock);
        l_token_item->last_update_token_time = l_token_update_item->updated_time;
    }
    if (ret != DAP_LEDGER_CHECK_WHITELISTED) {
        ret = s_token_tsd_parse(l_token_item, l_token, a_ledger, l_token->tsd_n_signs, l_tsd_total_size, true);
        assert(ret == DAP_LEDGER_CHECK_OK);
    }
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    const char *l_balance_dbg = NULL, *l_declare_update_str = NULL, *l_type_str = NULL;
    if (g_debug_ledger)
        dap_uint256_to_char(l_token->total_supply, &l_balance_dbg);
    switch (l_token->type) {
    case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL:       l_declare_update_str = "declared"; break;
    case DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE:     l_declare_update_str = "updated"; break;
    default: assert(false); break;
    }
    switch (l_token->subtype) {
    case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE:  l_type_str = "Simple"; break;
    case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE: l_type_str = "Private"; break;
    case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:  l_type_str = "CF20"; break;
    case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC:  l_type_str = "Public"; break;
    default: assert(false); break;
    }
    debug_if(g_debug_ledger, L_INFO, "%s token %s has been %s, total_supply: %s, signs_valid: %zu, signs_total: %zu",
                                l_type_str, l_token_item->ticker, l_declare_update_str,
                                l_balance_dbg, l_token_item->auth_signs_valid, l_token_item->auth_signs_total);
    s_ledger_token_cache_update(a_ledger, l_token_item);
    return ret;
}

int dap_ledger_token_load(dap_ledger_t *a_ledger, byte_t *a_token, size_t a_token_size, dap_time_t a_creation_time)
{
    if (dap_chain_net_get_load_mode(a_ledger->net)) {
        const char *l_ticker = NULL;
        switch (*(uint16_t *)a_token) {
        case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL:
            l_ticker = ((dap_chain_datum_token_t *)a_token)->ticker;
            break;
        case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_SIMPLE:
        case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PUBLIC:
        case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_NATIVE_DECL:
        case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_DECL:
            l_ticker = ((dap_chain_datum_token_old_t *)a_token)->ticker;
            break;
        }
        if (l_ticker && dap_ledger_pvt_find_token(a_ledger, l_ticker))
            return DAP_LEDGER_CHECK_OK;
    }
    return dap_ledger_token_add(a_ledger, a_token, a_token_size, a_creation_time);
}

/**
 * @brief dap_ledger_permissions_check
 * @param a_ledger Ledger object
 * @param a_token_item Token item
 * @param a_permission_id Permission type
 * @param a_addr Address to check
 * @return True if address has permission and effective time has passed
 */
static bool s_ledger_permissions_check(dap_ledger_t *a_ledger, dap_ledger_token_item_t *a_token_item, enum ledger_permissions a_permission_id, dap_chain_addr_t *a_addr)
{
    struct spec_address *l_addrs = NULL;
    size_t l_addrs_count = 0;
    switch (a_permission_id) {
    case LEDGER_PERMISSION_RECEIVER_ALLOWED:
        l_addrs = a_token_item->tx_recv_allow;
        l_addrs_count = a_token_item->tx_recv_allow_size;
    break;
    case LEDGER_PERMISSION_RECEIVER_BLOCKED:
        l_addrs = a_token_item->tx_recv_block;
        l_addrs_count = a_token_item->tx_recv_block_size;
    break;
    case LEDGER_PERMISSION_SENDER_ALLOWED:
        l_addrs = a_token_item->tx_send_allow;
        l_addrs_count = a_token_item->tx_send_allow_size;
    break;
    case LEDGER_PERMISSION_SENDER_BLOCKED:
        l_addrs = a_token_item->tx_send_block;
        l_addrs_count = a_token_item->tx_send_block_size;
    break;
    }
    for (size_t n = 0; n < l_addrs_count; n++)
        if (dap_chain_addr_compare(&l_addrs[n].addr, a_addr) &&
                l_addrs[n].becomes_effective <= dap_ledger_get_blockchain_time(a_ledger))
            return true;
    return false;
}

dap_ledger_check_error_t dap_ledger_pvt_addr_check(dap_ledger_t *a_ledger, dap_ledger_token_item_t *a_token_item, dap_chain_addr_t *a_addr, bool a_receive)
{
    dap_return_val_if_fail(a_token_item && a_addr, DAP_LEDGER_CHECK_INVALID_ARGS);
    if (dap_chain_addr_is_blank(a_addr))
        return DAP_LEDGER_CHECK_OK;
    if (a_receive) {
        if ((a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_BLOCKED) ||
                (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_FROZEN)) {
            // Check we are in white list
            if (!s_ledger_permissions_check(a_ledger, a_token_item, LEDGER_PERMISSION_RECEIVER_ALLOWED, a_addr))
                return DAP_LEDGER_CHECK_ADDR_FORBIDDEN;
        } else if ((a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_ALLOWED) ||
                (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_UNFROZEN)) {
            // Check we are in black list
            if (s_ledger_permissions_check(a_ledger, a_token_item, LEDGER_PERMISSION_RECEIVER_BLOCKED, a_addr))
                return DAP_LEDGER_CHECK_ADDR_FORBIDDEN;
        }
    } else {
        if ((a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_BLOCKED) ||
                (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_FROZEN)) {
            // Check we are in white list
            if (!s_ledger_permissions_check(a_ledger, a_token_item, LEDGER_PERMISSION_SENDER_ALLOWED, a_addr))
                return DAP_LEDGER_CHECK_ADDR_FORBIDDEN;
        } else if ((a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_ALLOWED) ||
                (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_UNFROZEN)) {
            // Check we are in black list
            if (s_ledger_permissions_check(a_ledger, a_token_item, LEDGER_PERMISSION_SENDER_BLOCKED, a_addr))
                return DAP_LEDGER_CHECK_ADDR_FORBIDDEN;
        }
    }
    return DAP_LEDGER_CHECK_OK;
}

int s_emission_add_check(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size, dap_chain_hash_fast_t *a_emission_hash,
                         dap_chain_datum_token_emission_t **a_emission, dap_ledger_token_item_t **a_token_item)
{
    dap_return_val_if_fail(a_token_emission && a_token_emission_size, DAP_LEDGER_CHECK_INVALID_ARGS);
    size_t l_emission_size = a_token_emission_size;
    dap_chain_datum_token_emission_t *l_emission = dap_chain_datum_emission_read(a_token_emission, &l_emission_size);
    if (!l_emission)
        return DAP_LEDGER_CHECK_INVALID_SIZE;
    if (l_emission->hdr.version < 3 && !a_token_item) { // It's mempool check
        log_it(L_WARNING, "Legacy emission version %hhu isn't supported for a new emissions", l_emission->hdr.version);
        DAP_DELETE(l_emission);
        return DAP_LEDGER_EMISSION_CHECK_LEGACY_FORBIDDEN;
    }
    dap_ledger_token_item_t *l_token_item = dap_ledger_pvt_find_token(a_ledger, l_emission->hdr.ticker);
    if (!l_token_item) {
        log_it(L_ERROR, "Check emission: token %s was not found", l_emission->hdr.ticker);
        DAP_DELETE(l_emission);
        return DAP_LEDGER_CHECK_TICKER_NOT_FOUND;
    }
    dap_ledger_token_emission_item_t *l_token_emission_item = NULL;
    // check if such emission is already present in table
    pthread_rwlock_rdlock(&l_token_item->token_emissions_rwlock);
    HASH_FIND(hh, l_token_item->token_emissions, a_emission_hash, sizeof(*a_emission_hash), l_token_emission_item);
    pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
    if (l_token_emission_item) {
        debug_if(g_debug_ledger, L_WARNING, "Can't add token emission datum of %s %s ( %s ): already present in cache",
                                    dap_uint256_to_char(l_emission->hdr.value, NULL), l_emission->hdr.ticker,
                                    dap_chain_hash_fast_to_str_static(a_emission_hash));
        DAP_DELETE(l_emission);
        return DAP_LEDGER_CHECK_ALREADY_CACHED;
    }

    if (! is_ledger_ems_chk(PVT(a_ledger)) )
        goto ret_success;

    // Check emission correctness
    if (IS_ZERO_256((l_emission->hdr.value))) {
        log_it(L_ERROR, "Emission check: zero %s emission value", l_token_item->ticker);
        DAP_DELETE(l_emission);
        return DAP_LEDGER_CHECK_ZERO_VALUE;
    }

    if (!dap_ledger_pvt_token_supply_check(l_token_item, l_emission->hdr.value)) {
        DAP_DELETE(l_emission);
        return DAP_LEDGER_EMISSION_CHECK_VALUE_EXCEEDS_CURRENT_SUPPLY;
    }

    //additional check for private tokens
    if((l_token_item->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE)
        ||  (l_token_item->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE)) {
        dap_ledger_check_error_t ret = dap_ledger_pvt_addr_check(a_ledger, l_token_item, &l_emission->hdr.address, true);
        if (ret == DAP_LEDGER_CHECK_ADDR_FORBIDDEN) {
            log_it(L_WARNING, "Address %s is not in allowed to receive for emission of token %s",
                            dap_chain_addr_to_str_static(&l_emission->hdr.address), l_token_item->ticker);
            DAP_DELETE(l_emission);
            return ret;
        }
    }
    switch (l_emission->hdr.type) {

    case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH: {
        size_t l_sign_data_check_size = sizeof(dap_chain_datum_token_emission_t) + l_emission->data.type_auth.tsd_total_size >= sizeof(dap_chain_datum_token_emission_t)
                                                ? sizeof(dap_chain_datum_token_emission_t) + l_emission->data.type_auth.tsd_total_size : 0;
        if (l_sign_data_check_size > l_emission_size) {
            if ( !dap_ledger_datum_is_enforced(a_ledger, a_emission_hash, true) ) {
                log_it(L_WARNING, "Incorrect size %zu of datum emission, expected at least %zu", l_emission_size, l_sign_data_check_size);
                DAP_DELETE(l_emission);
                return DAP_LEDGER_CHECK_INVALID_SIZE;
            }
            goto ret_success;
        }
        size_t l_emission_check_size = sizeof(dap_chain_datum_token_emission_t) + l_emission->data.type_auth.tsd_n_signs_size >= sizeof(dap_chain_datum_token_emission_t)
                                                ? sizeof(dap_chain_datum_token_emission_t) + l_emission->data.type_auth.tsd_n_signs_size : 0;
        if (l_emission_check_size != l_emission_size) {
            log_it(L_WARNING, "Incorrect size %zu of datum emission, must be %zu", l_emission_size, l_emission_check_size);
            DAP_DELETE(l_emission);
            return DAP_LEDGER_CHECK_INVALID_SIZE;
        }
        size_t l_signs_unique = l_emission->data.type_auth.signs_count;
        dap_sign_t **l_signs = dap_sign_get_unique_signs(l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size,
                                                         l_emission->data.type_auth.tsd_n_signs_size, &l_signs_unique);
        if (l_signs_unique < l_token_item->auth_signs_valid) {

            DAP_DELETE(l_signs);

            if ( !dap_ledger_datum_is_enforced(a_ledger, a_emission_hash, true) ) {

                log_it(L_WARNING, "The number of unique token signs %zu is less than total token signs set to %zu",
                       l_signs_unique, l_token_item->auth_signs_total);
                DAP_DELETE(l_emission);
                return DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS;
            }

            goto ret_success;
        }
        size_t l_sign_auth_count = l_emission->data.type_auth.signs_count;
        size_t l_sign_auth_size = l_emission->data.type_auth.tsd_n_signs_size;
        if (l_emission->hdr.version < 3) {
            l_sign_data_check_size = sizeof(l_emission->hdr);
        } else {
            l_emission->data.type_auth.signs_count = 0;
            l_emission->data.type_auth.tsd_n_signs_size = 0;
        }
        size_t l_aproves = 0;
        for (uint16_t i = 0; i < l_signs_unique; i++) {
            for (uint16_t k = 0; k < l_token_item->auth_signs_total; k++) {
                if (dap_pkey_compare_with_sign(l_token_item->auth_pkeys[k], l_signs[i])) {
                    // Verify if token emission is signed
                    if (!dap_sign_verify(l_signs[i], l_emission, l_sign_data_check_size))
                        l_aproves++;
                    break;
                }
            }
        }
        if (l_emission->hdr.version >= 3) {
            l_emission->data.type_auth.signs_count = l_sign_auth_count;
            l_emission->data.type_auth.tsd_n_signs_size = l_sign_auth_size;
        }
        DAP_DELETE(l_signs);
        if (l_aproves < l_token_item->auth_signs_valid && !dap_ledger_datum_is_enforced(a_ledger, a_emission_hash, true) ) {
            log_it(L_WARNING, "Emission of %s datoshi of %s:%s is wrong: only %zu valid aproves when %zu need",
                        dap_uint256_to_char(l_emission->hdr.value, NULL), a_ledger->net->pub.name, l_emission->hdr.ticker,
                        l_aproves, l_token_item->auth_signs_valid);
            debug_if(g_debug_ledger, L_ATT, "!!! Datum hash for HAL: %s", dap_chain_hash_fast_to_str_static(a_emission_hash));
            DAP_DELETE(l_emission);
            return DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS;
        }
    } break;

    default:
        log_it(L_ERROR, "Checking emission of type %s not implemented", dap_chain_datum_emission_type_str(l_emission->hdr.type));
        DAP_DELETE(l_emission);
        return DAP_LEDGER_CHECK_PARSE_ERROR;
    }

ret_success:
    if (a_token_item)
        *a_token_item = l_token_item;
    if (a_emission)
        *a_emission = l_emission;
    else
        DAP_DELETE(l_emission);

    return DAP_LEDGER_CHECK_OK;
}

int dap_ledger_token_emission_add_check(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size, dap_chain_hash_fast_t *a_emission_hash)
{
    return s_emission_add_check(a_ledger, a_token_emission, a_token_emission_size, a_emission_hash, NULL, NULL);
}

void dap_ledger_pvt_emission_cache_update(dap_ledger_t *a_ledger, dap_ledger_token_emission_item_t *a_emission_item)
{
    if (! is_ledger_cached(PVT(a_ledger)) )
        return;
    char *l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_EMISSIONS_STR);
    size_t l_cache_size = a_emission_item->datum_token_emission_size + sizeof(dap_hash_fast_t);
    uint8_t *l_cache = DAP_NEW_STACK_SIZE(uint8_t, l_cache_size);
    memcpy(l_cache, &a_emission_item->tx_used_out, sizeof(dap_hash_fast_t));
    memcpy(l_cache + sizeof(dap_hash_fast_t), a_emission_item->datum_token_emission, a_emission_item->datum_token_emission_size);
    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&a_emission_item->datum_token_emission_hash, l_hash_str, sizeof(l_hash_str));
    if (dap_global_db_set(l_gdb_group, l_hash_str, l_cache, l_cache_size, false, NULL, NULL)) {
        log_it(L_WARNING, "Ledger cache mismatch");
    }
    DAP_DELETE(l_gdb_group);
}

/**
 * @brief dap_ledger_token_emission_add
 * @param a_token_emission
 * @param a_token_emision_size
 * @return
 */

int dap_ledger_token_emission_add(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size, dap_hash_fast_t *a_emission_hash)
{
    dap_ledger_token_item_t *l_token_item = NULL;
    dap_chain_datum_token_emission_t *l_emission = NULL;
    int l_ret = s_emission_add_check(a_ledger, a_token_emission, a_token_emission_size, a_emission_hash, &l_emission, &l_token_item);
    if (l_ret != DAP_LEDGER_CHECK_OK)
        return l_ret;
    dap_ledger_token_emission_item_t *l_token_emission_item = NULL;
    // check if such emission is already present in table
    pthread_rwlock_wrlock(&l_token_item->token_emissions_rwlock);
    HASH_FIND(hh, l_token_item->token_emissions, a_emission_hash, sizeof(*a_emission_hash), l_token_emission_item);
    if (l_token_emission_item) {
        pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
        log_it(L_ERROR, "Duplicate token emission datum of %s %s ( %s )",
                dap_uint256_to_char(l_emission->hdr.value, NULL), l_emission->hdr.ticker, dap_hash_fast_to_str_static(a_emission_hash));
        DAP_DELETE(l_emission);
        return DAP_LEDGER_CHECK_APPLY_ERROR;
    }
    l_token_emission_item = DAP_NEW_Z(dap_ledger_token_emission_item_t);
    if (!l_token_emission_item) {
        pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
    }
    l_token_emission_item->datum_token_emission = l_emission;
    l_token_emission_item->datum_token_emission_hash = *a_emission_hash;
    HASH_ADD(hh, l_token_item->token_emissions, datum_token_emission_hash, sizeof(*a_emission_hash), l_token_emission_item);
    //Update value in ledger memory object
    if (!dap_ledger_pvt_token_supply_check_update(a_ledger, l_token_item, l_emission->hdr.value, false)) {
        HASH_DEL(l_token_item->token_emissions, l_token_emission_item);
        pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
        DAP_DELETE(l_emission);
        DAP_DELETE(l_token_emission_item);
        return DAP_LEDGER_CHECK_APPLY_ERROR;
    }
    pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
    // Add it to cache
    dap_ledger_pvt_emission_cache_update(a_ledger, l_token_emission_item);
    if (g_debug_ledger) {
        const char *l_balance; dap_uint256_to_char(l_token_emission_item->datum_token_emission->hdr.value, &l_balance);
        log_it(L_NOTICE, "Added token emission datum to emissions cache: type=%s value=%s token=%s to_addr=%s",
                       dap_chain_datum_emission_type_str(l_emission->hdr.type),
                       l_balance, l_emission->hdr.ticker,
                       dap_chain_addr_to_str_static(&(l_emission->hdr.address)));
    }
    if ( is_ledger_threshld(PVT(a_ledger)) )
        dap_ledger_pvt_threshold_txs_proc(a_ledger);
    return DAP_LEDGER_CHECK_OK;
}

int dap_ledger_token_emission_load(dap_ledger_t *a_ledger, byte_t *a_token_emission,
                                         size_t a_token_emission_size, dap_hash_fast_t *a_token_emission_hash)
{
    if (dap_chain_net_get_load_mode(a_ledger->net)) {
        dap_ledger_token_emission_item_t *l_token_emission_item = NULL;
        dap_ledger_token_item_t *l_token_item, *l_item_tmp;
        pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
        HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_item_tmp) {
            pthread_rwlock_rdlock(&l_token_item->token_emissions_rwlock);
            HASH_FIND(hh, l_token_item->token_emissions, a_token_emission_hash, sizeof(*a_token_emission_hash),
                    l_token_emission_item);
            pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
            if (l_token_emission_item) {
                pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
                return 0;
            }
        }
        pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    }
    return dap_ledger_token_emission_add(a_ledger, a_token_emission, a_token_emission_size, a_token_emission_hash);
}

dap_ledger_token_emission_item_t *dap_ledger_pvt_emission_item_find(dap_ledger_t *a_ledger,
                const char *a_token_ticker, const dap_chain_hash_fast_t *a_token_emission_hash, dap_ledger_token_item_t **a_token_item)
{
    dap_ledger_token_item_t *l_token_item = dap_ledger_pvt_find_token(a_ledger, a_token_ticker);
    if (!l_token_item)
        return NULL;
    else if (a_token_item)
        *a_token_item = l_token_item;
    dap_ledger_token_emission_item_t *l_token_emission_item = NULL;
    pthread_rwlock_rdlock(&l_token_item->token_emissions_rwlock);
    HASH_FIND(hh, l_token_item->token_emissions, a_token_emission_hash, sizeof(*a_token_emission_hash), l_token_emission_item);
    pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
    return l_token_emission_item;
}

/**
 * @brief dap_ledger_token_emission_find
 * @param a_token_ticker
 * @param a_token_emission_hash
 * @return
 */
dap_chain_datum_token_emission_t *dap_ledger_token_emission_find(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_token_emission_hash)
{
    dap_ledger_token_emission_item_t *l_emission_item = NULL;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    for (dap_ledger_token_item_t *l_item = PVT(a_ledger)->tokens; l_item; l_item = l_item->hh.next) {
         l_emission_item = dap_ledger_pvt_emission_item_find(a_ledger, l_item->ticker, a_token_emission_hash, NULL);
         if (l_emission_item)
             break;
    }
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    return l_emission_item ? l_emission_item->datum_token_emission : NULL;
}

const char *dap_ledger_get_description_by_ticker(dap_ledger_t *a_ledger, const char *a_token_ticker)
{
    dap_return_val_if_fail(a_ledger && a_token_ticker, NULL);
    dap_ledger_token_item_t *l_token_item = dap_ledger_pvt_find_token(a_ledger, a_token_ticker);
    return l_token_item ? l_token_item->description : NULL;
}

/**
 * @breif dap_ledger_token_get_auth_signs_valid
 * @param a_ledger
 * @param a_token_ticker
 * @return 0 if no ticker found
 */
size_t dap_ledger_token_get_auth_signs_valid(dap_ledger_t *a_ledger, const char *a_token_ticker)
{
    dap_ledger_token_item_t *l_token_item = dap_ledger_pvt_find_token(a_ledger, a_token_ticker);
    if (!l_token_item)
        return 0;
    return l_token_item->auth_signs_valid;
}

/**
 * @breif dap_ledger_token_get_auth_signs_total
 * @param a_ledger
 * @param a_token_ticker
 * @return
 */
size_t dap_ledger_token_get_auth_signs_total(dap_ledger_t *a_ledger, const char *a_token_ticker)
{
    dap_ledger_token_item_t *l_token_item = dap_ledger_pvt_find_token(a_ledger, a_token_ticker);
    if (!l_token_item)
        return 0;
    return l_token_item->auth_signs_total;
}

/**
 * @breif dap_ledger_token_auth_signs_hashes
 * @param a_ledger
 * @param a_token_ticker
 * @return
 */
dap_list_t *dap_ledger_token_get_auth_pkeys_hashes(dap_ledger_t *a_ledger, const char *a_token_ticker)
{
    dap_list_t *l_ret = NULL;
    dap_ledger_token_item_t *l_token_item = dap_ledger_pvt_find_token(a_ledger, a_token_ticker);
    if (!l_token_item)
        return l_ret;
    debug_if(g_debug_ledger, L_INFO, " ! Token %s : total %lu auth signs", a_token_ticker, l_token_item->auth_signs_total);
    for (size_t i = 0; i < l_token_item->auth_signs_total; i++)
        l_ret = dap_list_append(l_ret, l_token_item->auth_pkey_hashes + i);
    return l_ret;
}

uint256_t dap_ledger_token_get_emission_rate(dap_ledger_t *a_ledger, const char *a_token_ticker)
{
    dap_ledger_token_item_t *l_token_item = dap_ledger_pvt_find_token(a_ledger, a_token_ticker);
    if (!l_token_item || !l_token_item->is_delegated)
        return uint256_0;
    return l_token_item->emission_rate;
}

dap_json_t *s_token_item_to_json(dap_ledger_token_item_t *a_token_item, int a_version)
{
    dap_json_t *json_obj_datum = dap_json_object_new();
    const char *l_type_str = NULL;
    switch (a_token_item->subtype) {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE:
            l_type_str = "SIMPLE"; break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
            l_type_str = "PRIVATE"; break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
            l_type_str = "CF20"; break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC:
            l_type_str = "PUBLIC"; break;
        default: l_type_str = "UNKNOWN"; break;
    }
    dap_json_object_add_string(json_obj_datum, a_version == 1 ? "-->Token name" : "token_name", a_token_item->ticker);
    dap_json_object_add_string(json_obj_datum, a_version == 1 ? "type" : "subtype", l_type_str);
    if (a_token_item->subtype != DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE && a_token_item->subtype != DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC) {
        dap_chain_datum_token_flags_dump_to_json(json_obj_datum, "flags", a_token_item->flags);
        dap_json_object_add_string(json_obj_datum, "description", a_token_item->description ?
                               a_token_item->description :
                               "The token description is not set");
    }
    dap_json_object_add_string(json_obj_datum, a_version == 1 ? "Supply current" : "supply_current", dap_uint256_to_char(a_token_item->current_supply, NULL));
    dap_json_object_add_string(json_obj_datum, a_version == 1 ? "Supply total" : "supply_total", dap_uint256_to_char(a_token_item->total_supply, NULL));
    dap_json_object_add_string(json_obj_datum, a_version == 1 ? "Decimals" : "decimals", "18");
    dap_json_object_add_int(json_obj_datum, a_version == 1 ? "Auth signs valid" : "auth_sig_valid", a_token_item->auth_signs_valid);
    dap_json_object_add_int(json_obj_datum, a_version == 1 ? "Auth signs total" : "auth_sig_total", a_token_item->auth_signs_total);
    dap_json_t *l_json_arr_pkeys = dap_json_array_new();
    for (uint16_t i = 0; i < a_token_item->auth_signs_total; i++) {
        dap_json_t *l_json_obj_out = dap_json_object_new();
        dap_json_object_add_int(l_json_obj_out, "line", i);
        dap_json_object_add_string(l_json_obj_out, a_version == 1 ? "hash" : "pkey_hash", dap_hash_fast_to_str_static(a_token_item->auth_pkey_hashes + i));
        dap_json_object_add_string(l_json_obj_out, "pkey_type", dap_pkey_type_to_str(a_token_item->auth_pkeys[i]->header.type));
        dap_json_object_add_int(l_json_obj_out, a_version == 1 ? "bytes" : "pkey_size", a_token_item->auth_pkeys[i]->header.size);
        dap_json_array_add(l_json_arr_pkeys, l_json_obj_out);
    }
    dap_json_t *l_json_arr_tx_recv_allow = dap_json_array_new();
    for (size_t i = 0; i < a_token_item->tx_recv_allow_size; i++) {
        dap_chain_addr_t l_addr = a_token_item->tx_recv_allow[i].addr;
        const char *l_addr_str = dap_chain_addr_to_str_static(&l_addr);
        dap_json_t *l_addr_obj = dap_json_object_new_string(l_addr_str);
        dap_json_array_add(l_json_arr_tx_recv_allow, l_addr_obj);
    }
    dap_json_t *l_json_arr_tx_recv_block = dap_json_array_new();
    for (size_t i = 0; i < a_token_item->tx_recv_block_size; i++) {
        dap_chain_addr_t l_addr = a_token_item->tx_recv_block[i].addr;
        const char *l_addr_str = dap_chain_addr_to_str_static(&l_addr);
        dap_json_t *l_addr_obj = dap_json_object_new_string(l_addr_str);
        dap_json_array_add(l_json_arr_tx_recv_block, l_addr_obj);
    }
    dap_json_t *l_json_arr_tx_send_allow = dap_json_array_new();
    for (size_t i = 0; i < a_token_item->tx_send_allow_size; i++) {
        dap_chain_addr_t l_addr = a_token_item->tx_send_allow[i].addr;
        const char *l_addr_str = dap_chain_addr_to_str_static(&l_addr);
        dap_json_t *l_addr_obj = dap_json_object_new_string(l_addr_str);
        dap_json_array_add(l_json_arr_tx_send_allow, l_addr_obj);
    }
    dap_json_t *l_json_arr_tx_send_block = dap_json_array_new();
    for (size_t i = 0; i < a_token_item->tx_send_block_size; i++) {
        dap_chain_addr_t l_addr = a_token_item->tx_send_block[i].addr;
        const char *l_addr_str = dap_chain_addr_to_str_static(&l_addr);
        dap_json_t *l_addr_obj = dap_json_object_new_string(l_addr_str);
        dap_json_array_add(l_json_arr_tx_send_block, l_addr_obj);
    }
    dap_json_object_add_array(json_obj_datum, a_version == 1 ? "Signatures public keys" : "sig_pkeys", l_json_arr_pkeys);
    a_token_item->tx_recv_allow_size ? dap_json_object_add_array(json_obj_datum, "tx_recv_allow", l_json_arr_tx_recv_allow) :
        dap_json_object_free(l_json_arr_tx_recv_allow);
    a_token_item->tx_recv_block_size ? dap_json_object_add_array(json_obj_datum, "tx_recv_block", l_json_arr_tx_recv_block) :
        dap_json_object_free(l_json_arr_tx_recv_block);
    a_token_item->tx_send_allow_size ? dap_json_object_add_array(json_obj_datum, "tx_send_allow", l_json_arr_tx_send_allow) :
        dap_json_object_free(l_json_arr_tx_send_allow);
    a_token_item->tx_send_block_size ? dap_json_object_add_array(json_obj_datum, "tx_send_block", l_json_arr_tx_send_block) :
        dap_json_object_free(l_json_arr_tx_send_block);
    dap_json_object_add_int(json_obj_datum, a_version == 1 ? "Total emissions" : "total_emissions", HASH_COUNT(a_token_item->token_emissions));
    return json_obj_datum;
}

/**
 * @brief Compose string list of all tokens with information
 * @param a_ledger
 * @return
 */
dap_json_t *dap_ledger_token_info(dap_ledger_t *a_ledger, size_t a_limit, size_t a_offset, int a_version)
{
    dap_json_t * json_obj_datum;
    dap_json_t * json_arr_out = dap_json_array_new();
    dap_ledger_token_item_t *l_token_item, *l_tmp_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    size_t l_arr_start = 0;
    if (a_offset > 0) {
        l_arr_start = a_offset;
        dap_json_t* json_obj_tx = dap_json_object_new();
        dap_json_object_add_int(json_obj_tx, "offset", l_arr_start);
        dap_json_array_add(json_arr_out, json_obj_tx);
    }
    size_t l_arr_end = HASH_COUNT(PVT(a_ledger)->tokens);
    if (a_limit) {
        dap_json_t* json_obj_tx = dap_json_object_new();
        dap_json_object_add_int(json_obj_tx, "limit", a_limit);
        dap_json_array_add(json_arr_out, json_obj_tx);
        l_arr_end = l_arr_start + a_limit;
        if (l_arr_end > HASH_COUNT(PVT(a_ledger)->tokens)) {
            l_arr_end = HASH_COUNT(PVT(a_ledger)->tokens);
        }
    }
    size_t i = 0;
    HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_tmp_item) {
        if (i < l_arr_start || i >= l_arr_end) {
            i++;
            continue;
        }
        json_obj_datum = s_token_item_to_json(l_token_item, a_version);
        dap_json_array_add(json_arr_out, json_obj_datum);
        i++;
    }
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    return json_arr_out;
}

/**
 * @breif Forms a JSON object with a token description for the specified ticker.
 * @param a_ledger
 * @param a_token_ticker
 * @return
 */
dap_json_t *dap_ledger_token_info_by_name(dap_ledger_t *a_ledger, const char *a_token_ticker, int a_version)
{
    dap_ledger_token_item_t *l_token_item = NULL;
    HASH_FIND_STR(PVT(a_ledger)->tokens, a_token_ticker, l_token_item);
    if (l_token_item)
        return s_token_item_to_json(l_token_item, a_version);
    return NULL;
}

/**
 * @brief Get all token declatations
 * @param a_ledger
 * @return
 */
dap_list_t* dap_ledger_token_decl_all(dap_ledger_t *a_ledger)
{
    dap_list_t * l_ret = NULL;
    dap_ledger_token_item_t *l_token_item, *l_tmp_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);

    HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_tmp_item) {
        dap_chain_datum_token_t *l_token = l_token_item->datum_token;
        l_ret = dap_list_append(l_ret, l_token);
    }
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    return l_ret;
}

/**
 * @brief Get list of all tickets for ledger and address. If address is NULL returns all the tockens present in system
 * @param a_ledger
 * @param a_addr
 * @param a_tickers
 * @param a_tickers_size
 */
void dap_ledger_addr_get_token_ticker_all(dap_ledger_t *a_ledger, dap_chain_addr_t * a_addr,
        char *** a_tickers, size_t * a_tickers_size)
{
    if (a_addr == NULL){ // Get all tockens
        pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
        size_t l_count = HASH_COUNT(PVT(a_ledger)->tokens);
        if (l_count && a_tickers){
            dap_ledger_token_item_t * l_token_item, *l_tmp;
            char **l_tickers = DAP_NEW_Z_SIZE(char*, l_count * sizeof(char*));
            if (!l_tickers) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                pthread_rwlock_unlock(&PVT(a_ledger)->balance_accounts_rwlock);
                return;
            }
            l_count = 0;
            HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_tmp) {
                l_tickers[l_count] = dap_strdup(l_token_item->ticker);
                l_count++;
            }
            *a_tickers = l_tickers;
        }
        pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
        if(a_tickers_size)
            *a_tickers_size = l_count;
    }else{ // Calc only tokens from address balance
        dap_ledger_wallet_balance_t *wallet_balance, *tmp;
        size_t l_count = HASH_COUNT(PVT(a_ledger)->balance_accounts);
        if(l_count && a_tickers){
            char **l_tickers = DAP_NEW_Z_SIZE(char*, l_count * sizeof(char*));
            if (!l_tickers) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                pthread_rwlock_unlock(&PVT(a_ledger)->balance_accounts_rwlock);
                return;
            }
            l_count = 0;
            const char *l_addr = dap_chain_addr_to_str_static(a_addr);
            pthread_rwlock_rdlock(&PVT(a_ledger)->balance_accounts_rwlock);
            HASH_ITER(hh, PVT(a_ledger)->balance_accounts, wallet_balance, tmp) {
                char **l_keys = dap_strsplit(wallet_balance->key, " ", -1);
                if (!dap_strcmp(l_keys[0], l_addr)) {
                    l_tickers[l_count] = dap_strdup(wallet_balance->token_ticker);
                    ++l_count;
                }
                dap_strfreev(l_keys);
            }
            pthread_rwlock_unlock(&PVT(a_ledger)->balance_accounts_rwlock);
            *a_tickers = l_tickers;
        }
        if(a_tickers_size)
            *a_tickers_size = l_count;
    }
}

#if 0 /// No working code, ts_added is illegal timestamp
/**
 * @brief Mark token emissions created after hardfork time
 * @param a_ledger Ledger instance
 * @param a_hardfork_time Hardfork timestamp
 * @return 0 on success, negative error code otherwise
 */
int dap_ledger_token_emissions_mark_hardfork(dap_ledger_t *a_ledger, dap_time_t a_hardfork_time)
{
    if (!a_ledger) {
        log_it(L_ERROR, "NULL ledger provided");
        return -1;
    }
    
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    dap_ledger_token_item_t *l_token_item = NULL, *l_token_tmp = NULL;
    HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_token_tmp) {
        dap_ledger_token_emission_item_t *l_emission = NULL, *l_emission_tmp = NULL;
        HASH_ITER(hh, l_token_item->token_emissions, l_emission, l_emission_tmp) {
            // Mark emissions created at or after hardfork time
            // Convert nanotime to seconds for comparison
            dap_time_t l_emission_time = (dap_time_t)(l_emission->ts_added / 1000000000ULL);
            if (l_emission_time >= a_hardfork_time) {
                l_emission->is_hardfork = true;
            }
        }
    }
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    
    log_it(L_NOTICE, "Token emissions marked for hardfork at time %"DAP_UINT64_FORMAT_U, a_hardfork_time);
    return 0;
}
#else
/**
 * @brief Mark all token emissions created before hardfork time as spent
 * @details This function iterates through all tokens and their emissions, marking those
 * created before the specified hardfork time as spent by setting tx_used_out 
 * to a special hash with all bits set to 1 (0xFF...FF).
 * @param a_ledger Ledger object to process
 * @param a_hardfork_time Cutoff time - emissions created before this time will be marked as spent
 * @return Number of emissions marked as spent, or -1 on error
 */
int dap_ledger_token_emissions_mark_hardfork(dap_ledger_t *a_ledger, dap_time_t a_hardfork_time)
{
    dap_return_val_if_fail(a_ledger, -1);
    
    // Create special hash with all bits set to 1 to mark hardfork-spent emissions
    dap_chain_hash_fast_t l_hardfork_hash;
    memset(&l_hardfork_hash, 0xFF, DAP_CHAIN_HASH_FAST_SIZE);
    
    int l_marked_count = 0;
    
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    
    dap_ledger_token_item_t *l_token_item, *l_tmp_token;
    HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_tmp_token) {
        pthread_rwlock_wrlock(&l_token_item->token_emissions_rwlock);
        
        dap_ledger_token_emission_item_t *l_emission_item, *l_tmp_emission;
        HASH_ITER(hh, l_token_item->token_emissions, l_emission_item, l_tmp_emission) {
            // Check if emission is already marked as used
            if (!dap_hash_fast_is_blank(&l_emission_item->tx_used_out))
                continue; // Skip already used emissions
            
            // Check if emission was created before hardfork time
            dap_time_t l_emission_time = 0;
            dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_ledger->net, CHAIN_TYPE_EMISSION);
            if (l_chain) {
                dap_hash_fast_t l_atom_hash = { };
                l_chain->callback_datum_find_by_hash(l_chain, &l_emission_item->datum_token_emission_hash, &l_atom_hash, NULL);
                dap_chain_atom_iter_t *l_atom_iter = l_chain->callback_atom_iter_create(l_chain, c_dap_chain_cell_id_null, &l_atom_hash);
                if (l_atom_iter && l_atom_iter->cur) {
                    l_emission_time = l_atom_iter->cur_ts;
                    l_chain->callback_atom_iter_delete(l_atom_iter);
                }
            }

            if (l_emission_time && l_emission_time < a_hardfork_time) {
                // Mark emission as spent with hardfork hash
                l_emission_item->tx_used_out = l_hardfork_hash;
                l_marked_count++;
                
                // Update cache if ledger uses caching
                dap_ledger_pvt_emission_cache_update(a_ledger, l_emission_item);
                
                debug_if(g_debug_ledger, L_INFO, "Marked emission %s of token %s as hardfork-spent", 
                        dap_chain_hash_fast_to_str_static(&l_emission_item->datum_token_emission_hash),
                        l_token_item->ticker);
            }
        }
        
        pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
    }
    
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    
    log_it(L_NOTICE, "Hardfork processing complete: marked %d emissions as spent", l_marked_count);
    return l_marked_count;
}
#endif
