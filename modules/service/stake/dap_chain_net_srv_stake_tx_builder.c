/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 */

#include "dap_chain_net_srv_stake_tx_builder.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_tx_compose_api.h"
#include "dap_chain_datum.h"
#include "dap_chain_ledger.h"      // For dap_ledger_sign_data
#include "dap_chain_tx_sign.h"     // For dap_chain_tx_sign_add
#include "dap_chain_utxo.h"        // For dap_chain_tx_used_out_t
#include "dap_common.h"

#define LOG_TAG "dap_stake_tx_builder"

// ============================================================================
// TX Builder Functions (PURE - create unsigned TX from used outputs)
// ============================================================================

/**
 * @brief Create unsigned stake lock transaction
 */
dap_chain_datum_tx_t *dap_stake_tx_create_lock(
    dap_list_t *a_list_used_outs,
    const dap_chain_addr_t *a_wallet_addr,
    const char *a_main_ticker,
    uint256_t a_value,
    uint256_t a_value_fee,
    dap_time_t a_time_staking,
    uint256_t a_reinvest_percent,
    const char *a_delegated_ticker,
    uint256_t a_delegated_value,
    dap_chain_id_t a_chain_id,
    dap_chain_srv_uid_t a_srv_uid
) {
    dap_return_val_if_fail(a_list_used_outs && a_wallet_addr && a_main_ticker, NULL);
    
    // Calculate total input value
    uint256_t l_value_found = {};
    for (dap_list_t *l_iter = a_list_used_outs; l_iter; l_iter = l_iter->next) {
        dap_chain_tx_used_out_t *l_used_out = (dap_chain_tx_used_out_t *)l_iter->data;
        if (l_used_out) {
            SUM_256_256(l_value_found, l_used_out->value, &l_value_found);
        }
    }
    
    // Verify we have enough funds
    uint256_t l_total_need = {};
    SUM_256_256(a_value, a_value_fee, &l_total_need);
    if (compare256(l_value_found, l_total_need) < 0) {
        log_it(L_ERROR, "Insufficient funds for stake lock");
        return NULL;
    }
    
    // Create empty TX
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create TX");
        return NULL;
    }
    
    // Add inputs from used outputs
    for (dap_list_t *l_iter = a_list_used_outs; l_iter; l_iter = l_iter->next) {
        dap_chain_tx_used_out_t *l_used_out = (dap_chain_tx_used_out_t *)l_iter->data;
        if (!l_used_out) continue;
        
        if (dap_chain_datum_tx_add_in_item(&l_tx, &l_used_out->tx_prev_hash, l_used_out->tx_out_prev_idx) != 1) {
            log_it(L_ERROR, "Failed to add input item");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    
    // Create stake lock conditional output
    // TODO: Add ticker and delegated parameters support
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_stake_lock(
        a_srv_uid,
        a_value,
        a_time_staking,  // time_unlock
        a_reinvest_percent
    );
    
    UNUSED(a_main_ticker);
    UNUSED(a_delegated_ticker);
    UNUSED(a_delegated_value);
    UNUSED(a_chain_id);
    
    if (!l_tx_out_cond) {
        log_it(L_ERROR, "Failed to create stake lock conditional output");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // Add conditional output to TX
    if (dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out_cond) != 1) {
        log_it(L_ERROR, "Failed to add conditional output");
        DAP_DELETE(l_tx_out_cond);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    DAP_DELETE(l_tx_out_cond);
    
    // Add change output if needed
    uint256_t l_change = {};
    SUBTRACT_256_256(l_value_found, l_total_need, &l_change);
    if (!IS_ZERO_256(l_change)) {
        if (dap_chain_datum_tx_add_out_item(&l_tx, a_wallet_addr, l_change) != 1) {
            log_it(L_ERROR, "Failed to add change output");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    
    // Add fee
    if (!IS_ZERO_256(a_value_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
            log_it(L_ERROR, "Failed to add fee");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    
    log_it(L_INFO, "Created unsigned stake lock transaction");
    return l_tx;
}

/**
 * @brief Create unsigned stake unlock transaction
 */
dap_chain_datum_tx_t *dap_stake_tx_create_unlock(
    dap_list_t *a_list_used_outs,
    dap_hash_fast_t *a_stake_tx_hash,
    uint32_t a_prev_cond_idx,
    const char *a_main_ticker,
    uint256_t a_value,
    uint256_t a_value_fee,
    const char *a_delegated_ticker,
    uint256_t a_delegated_value
) {
    dap_return_val_if_fail(a_stake_tx_hash && a_main_ticker, NULL);
    
    // TODO: Implement stake unlock
    // This needs to:
    // 1. Add in_cond item pointing to stake lock TX
    // 2. Add outputs for unlocked tokens
    // 3. Add fee
    
    log_it(L_WARNING, "Stake unlock TX builder not yet implemented");
    UNUSED(a_list_used_outs); UNUSED(a_prev_cond_idx); UNUSED(a_value);
    UNUSED(a_value_fee); UNUSED(a_delegated_ticker); UNUSED(a_delegated_value);
    
    return NULL;
}

/**
 * @brief Create unsigned stake delegation transaction
 */
dap_chain_datum_tx_t *dap_stake_tx_create_delegate(
    dap_list_t *a_list_used_outs,
    uint256_t a_value,
    uint256_t a_fee,
    const dap_chain_addr_t *a_signing_addr,
    const dap_chain_node_addr_t *a_node_addr,
    const dap_chain_addr_t *a_sovereign_addr,
    uint256_t a_sovereign_tax,
    dap_chain_datum_tx_t *a_prev_tx,
    dap_chain_srv_uid_t a_srv_uid
) {
    dap_return_val_if_fail(a_signing_addr && a_node_addr, NULL);
    
    // TODO: Implement stake delegation
    // This is more complex - needs to create conditional output with delegation info
    
    log_it(L_WARNING, "Stake delegate TX builder not yet implemented");
    UNUSED(a_list_used_outs); UNUSED(a_value); UNUSED(a_fee);
    UNUSED(a_sovereign_addr); UNUSED(a_sovereign_tax); UNUSED(a_prev_tx); UNUSED(a_srv_uid);
    
    return NULL;
}

/**
 * @brief Create unsigned stake invalidation transaction
 */
dap_chain_datum_tx_t *dap_stake_tx_create_invalidate(
    dap_list_t *a_list_used_outs,
    dap_hash_fast_t *a_tx_hash,
    uint256_t a_fee
) {
    dap_return_val_if_fail(a_tx_hash, NULL);
    
    // TODO: Implement stake invalidation
    
    log_it(L_WARNING, "Stake invalidate TX builder not yet implemented");
    UNUSED(a_list_used_outs); UNUSED(a_fee);
    
    return NULL;
}

// ============================================================================
// TX Compose API Integration (Callbacks + Registration)
// ============================================================================

/**
 * @brief Parameters for stake lock compose callback
 */
typedef struct {
    const dap_chain_addr_t *wallet_addr;  // For change output
    const char *main_ticker;
    uint256_t value;
    uint256_t fee;
    dap_time_t time_staking;
    uint256_t reinvest_percent;
    const char *delegated_ticker;
    uint256_t delegated_value;
    dap_chain_id_t chain_id;
    dap_chain_srv_uid_t srv_uid;
    const char *wallet_name;  // For signing
} stake_lock_params_t;

/**
 * @brief TX Compose callback for stake lock
 */
static dap_chain_datum_t* s_stake_lock_compose_cb(
    dap_ledger_t *a_ledger,
    dap_list_t *a_list_used_outs,
    void *a_params
)
{
    stake_lock_params_t *l_params = (stake_lock_params_t *)a_params;
    if (!l_params || !l_params->wallet_name || !l_params->wallet_addr) {
        log_it(L_ERROR, "Invalid stake lock parameters");
        return NULL;
    }
    
    // 1. Build unsigned TX
    dap_chain_datum_tx_t *l_tx = dap_stake_tx_create_lock(
        a_list_used_outs,
        l_params->wallet_addr,
        l_params->main_ticker,
        l_params->value,
        l_params->fee,
        l_params->time_staking,
        l_params->reinvest_percent,
        l_params->delegated_ticker,
        l_params->delegated_value,
        l_params->chain_id,
        l_params->srv_uid
    );
    
    if (!l_tx) {
        log_it(L_ERROR, "Failed to build stake lock TX");
        return NULL;
    }
    
    // 2. Get sign data
    size_t l_sign_data_size = 0;
    const void *l_sign_data = dap_chain_tx_get_signing_data(l_tx, &l_sign_data_size);
    if (!l_sign_data) {
        log_it(L_ERROR, "Failed to get signing data");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // 3. Sign via ledger
    dap_sign_t *l_sign = dap_ledger_sign_data(a_ledger, l_params->wallet_name, 
                                                l_sign_data, l_sign_data_size, 0);
    if (!l_sign) {
        log_it(L_ERROR, "Failed to sign stake lock TX");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // 4. Add signature
    if (dap_chain_tx_sign_add(&l_tx, l_sign) != 0) {
        log_it(L_ERROR, "Failed to add signature");
        DAP_DELETE(l_sign);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // 5. Convert to datum
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, 
                                                         dap_chain_datum_tx_get_size(l_tx));
    dap_chain_datum_tx_delete(l_tx);
    
    return l_datum;
}

/**
 * @brief Register stake TX builders
 */
int dap_stake_tx_builders_register(void)
{
    log_it(L_INFO, "Registering stake TX builders...");
    
    int l_ret = dap_chain_tx_compose_register("stake_lock", s_stake_lock_compose_cb, NULL);
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to register stake_lock builder");
        return l_ret;
    }
    
    // TODO: Register other stake TX types:
    // - stake_unlock
    // - stake_delegate
    // - stake_invalidate
    
    log_it(L_NOTICE, "Stake TX builders registered successfully");
    return 0;
}

/**
 * @brief Unregister stake TX builders
 */
void dap_stake_tx_builders_unregister(void)
{
    log_it(L_INFO, "Unregistering stake TX builders...");
    
    dap_chain_tx_compose_unregister("stake_lock");
    // TODO: Unregister other types
    
    log_it(L_NOTICE, "Stake TX builders unregistered");
}

