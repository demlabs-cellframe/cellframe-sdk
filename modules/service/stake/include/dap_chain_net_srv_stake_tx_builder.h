/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 */

#pragma once

#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_list.h"
#include "dap_pkey.h"
#include "dap_hash.h"

/**
 * @file dap_chain_net_srv_stake_tx_builder.h
 * @brief Stake Transaction Builders - PURE FUNCTIONS
 *
 * These functions create UNSIGNED stake transactions.
 * They follow the same pattern as wallet TX builders.
 */

/**
 * @brief Create unsigned stake lock transaction from used outputs
 *
 * @param a_list_used_outs List of used outputs (dap_chain_tx_used_out_t*)
 * @param a_wallet_addr Wallet address (for change output)
 * @param a_main_ticker Token ticker to stake
 * @param a_value Amount to stake
 * @param a_value_fee Fee amount
 * @param a_time_staking Staking duration
 * @param a_reinvest_percent Reinvestment percentage (0-10000)
 * @param a_delegated_ticker Optional delegated ticker (can be NULL)
 * @param a_delegated_value Optional delegated value
 * @param a_chain_id Chain ID
 * @param a_srv_uid Service UID
 * @return Unsigned transaction or NULL on error. Must be freed by caller.
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
);

/**
 * @brief Create unsigned stake unlock transaction from used outputs
 *
 * @param a_list_used_outs List of used outputs
 * @param a_stake_tx_hash Hash of stake lock transaction
 * @param a_prev_cond_idx Index of conditional output
 * @param a_main_ticker Token ticker
 * @param a_value Unlock value
 * @param a_value_fee Fee amount
 * @param a_delegated_ticker Optional delegated ticker
 * @param a_delegated_value Optional delegated value
 * @return Unsigned transaction or NULL on error
 */
dap_chain_datum_tx_t *dap_stake_tx_create_unlock(
    dap_list_t *a_list_used_outs,
    dap_hash_sha3_256_t *a_stake_tx_hash,
    uint32_t a_prev_cond_idx,
    const char *a_main_ticker,
    uint256_t a_value,
    uint256_t a_value_fee,
    const char *a_delegated_ticker,
    uint256_t a_delegated_value
);

/**
 * @brief Create unsigned stake delegation transaction
 *
 * @param a_list_used_outs List of used outputs
 * @param a_value Delegation value
 * @param a_fee Fee amount
 * @param a_signing_addr Signing address
 * @param a_node_addr Node address
 * @param a_sovereign_addr Optional sovereign address
 * @param a_sovereign_tax Sovereign tax
 * @param a_prev_tx Previous transaction
 * @param a_srv_uid Service UID
 * @return Unsigned transaction or NULL on error
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
);

/**
 * @brief Create unsigned stake invalidation transaction
 *
 * @param a_list_used_outs List of used outputs
 * @param a_tx_hash Hash of transaction to invalidate
 * @param a_fee Fee amount
 * @return Unsigned transaction or NULL on error
 */
dap_chain_datum_tx_t *dap_stake_tx_create_invalidate(
    dap_list_t *a_list_used_outs,
    dap_hash_sha3_256_t *a_tx_hash,
    uint256_t a_fee
);

/**
 * @brief Register stake TX builders in TX Compose API
 *
 * Called during stake module initialization.
 * Registers all stake transaction types with TX Compose Plugin system.
 *
 * @return 0 on success, negative on error
 */
int dap_stake_tx_builders_register(void);

/**
 * @brief Unregister stake TX builders
 *
 * Called during stake module deinitialization.
 */
void dap_stake_tx_builders_unregister(void);

