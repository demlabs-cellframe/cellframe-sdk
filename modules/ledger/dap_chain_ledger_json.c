/**
 * @file dap_chain_ledger_json.c
 * @brief JSON-related functions for ledger transaction outputs
 * @details Moved from compose module to break circular dependencies
 * 
 * @date 2025-10-05
 */

#include "dap_chain_ledger.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_json.h"
#include "dap_common.h"


#define LOG_TAG "dap_chain_ledger_json"

/**
 * @brief Get list of transaction outputs from JSON array
 * @param a_outputs_array JSON array of outputs
 * @param a_outputs_count Number of outputs in array
 * @param a_value_need Required value
 * @param a_value_transfer[out] Actual transferred value
 * @param a_need_all_outputs Get all outputs or stop when value is reached
 * @return List of dap_chain_tx_used_out_item_t or NULL
 */
dap_list_t *dap_ledger_get_list_tx_outs_from_json(dap_json_t *a_outputs_array, int a_outputs_count, 
                                                     uint256_t a_value_need, uint256_t *a_value_transfer, 
                                                     bool a_need_all_outputs)
{
#ifdef DAP_CHAIN_TX_COMPOSE_TEST
    size_t l_out_count = rand() % 10 + 1;
    dap_list_t *l_ret = NULL;
    for (size_t i = 0; i < l_out_count; ++i) {
        dap_chain_tx_used_out_item_t *l_item = DAP_NEW_Z(dap_chain_tx_used_out_item_t);
        randombytes(l_item, sizeof(dap_chain_tx_used_out_item_t));
        l_ret = dap_list_append(l_ret, l_item);
    }
    return l_ret;
#endif
    if (!a_outputs_array || a_outputs_count <= 0) {
        return NULL;
    }

    dap_list_t *l_list_used_out = NULL;
    uint256_t l_value_transfer = {};

    for (int i = 0; i < a_outputs_count; i++) {
        dap_json_t *l_output = dap_json_array_get_idx(a_outputs_array, i);
        if (!l_output || !dap_json_is_object(l_output)) {
            continue;
        }
        
        dap_json_t *l_value_datosi_obj = NULL;
        dap_json_object_get_ex(l_output, "value_datosi", &l_value_datosi_obj);
        if (!l_value_datosi_obj) {
            continue;
        }
        const char *l_value_str = dap_json_get_string(l_value_datosi_obj);
        uint256_t l_value = dap_chain_balance_scan(l_value_str);

        if (IS_ZERO_256(l_value)) {
            continue;
        }

        dap_json_t *l_prev_hash_obj = NULL;
        dap_json_object_get_ex(l_output, "prev_hash", &l_prev_hash_obj);
        if (!l_prev_hash_obj) {
            continue;
        }
        const char *l_prev_hash_str = dap_json_get_string(l_prev_hash_obj);
        
        dap_json_t *l_out_prev_idx_obj = NULL;
        dap_json_object_get_ex(l_output, "out_prev_idx", &l_out_prev_idx_obj);
        if (!l_out_prev_idx_obj) {
            continue;
        }
        int l_out_idx = dap_json_object_get_int(l_out_prev_idx_obj, NULL);

        dap_chain_tx_used_out_item_t *l_item = DAP_NEW_Z(dap_chain_tx_used_out_item_t);
        if (!l_item) {
            continue;
        }

        if (dap_chain_hash_fast_from_str(l_prev_hash_str, &l_item->tx_hash_fast)) {
            DAP_DELETE(l_item);
            continue;
        }

        l_item->num_idx_out = l_out_idx;
        l_item->value = l_value;

        l_list_used_out = dap_list_append(l_list_used_out, l_item);
        if (!l_list_used_out) {
            DAP_DELETE(l_item);
            return NULL;
        }
        
        SUM_256_256(l_value_transfer, l_value, &l_value_transfer);

        if (!a_need_all_outputs && compare256(l_value_transfer, a_value_need) >= 0) {
            break;
        }
    }

    if (compare256(l_value_transfer, a_value_need) >= 0 && l_list_used_out) {
        if (a_value_transfer) {
            *a_value_transfer = l_value_transfer;
        }
        return l_list_used_out;
    }

    // Not enough value, clean up
    dap_list_free_full(l_list_used_out, NULL);
    return NULL;
}


