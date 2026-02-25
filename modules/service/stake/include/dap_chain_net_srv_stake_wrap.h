/**
 * @file dap_chain_net_srv_stake_wrap.h
 * @brief Wrapper functions for stake service operations
 * 
 * This file declares wrapper functions for stake operations that can be
 * mocked during unit testing. The wrappers provide an indirection layer
 * between CLI commands and actual stake logic.
 * 
 * @author Cellframe Team
 * @copyright DeM Labs Inc. 2025
 * @license GPL-3.0
 */

#pragma once

#include "dap_chain_net_srv_stake_pos_delegate.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Wrapper for getting validators list
 * @param a_net_id Network ID
 * @param a_only_active Only return active validators
 * @param a_excluded_list Output list of excluded validators
 * @return List of validators
 */
dap_list_t *dap_chain_net_srv_stake_get_validators_w(
    dap_chain_net_id_t a_net_id, 
    bool a_only_active, 
    uint16_t **a_excluded_list);

/**
 * @brief Wrapper for getting total stake weight
 * @param a_net_id Network ID
 * @param a_locked_weight Output: locked weight
 * @return Total weight
 */
uint256_t dap_chain_net_srv_stake_get_total_weight_w(
    dap_chain_net_id_t a_net_id, 
    uint256_t *a_locked_weight);

/**
 * @brief Wrapper for getting total number of delegated keys
 * @param a_net_id Network ID
 * @param a_in_active_count Output: count of inactive keys
 * @return Total number of keys
 */
size_t dap_chain_net_srv_stake_get_total_keys_w(
    dap_chain_net_id_t a_net_id, 
    size_t *a_in_active_count);

/**
 * @brief Wrapper for getting minimum allowed stake value
 * @param a_net_id Network ID
 * @return Minimum allowed stake value
 */
uint256_t dap_chain_net_srv_stake_get_allowed_min_value_w(
    dap_chain_net_id_t a_net_id);

/**
 * @brief Wrapper for checking validator
 * @param a_net Network pointer
 * @param a_tx_hash Transaction hash
 * @param out_data Output validation data
 * @param a_time_connect Connection timeout
 * @param a_time_response Response timeout
 * @return 0 on success, error code otherwise
 */
int dap_chain_net_srv_stake_check_validator_w(
    dap_chain_net_t *a_net, 
    dap_hash_fast_t *a_tx_hash, 
    dap_chain_ch_validator_test_t *out_data,
    int a_time_connect, 
    int a_time_response);

/**
 * @brief Wrapper for getting maximum stake percentage
 * @param a_net_id Network ID
 * @return Maximum stake percentage
 */
uint256_t dap_chain_net_srv_stake_get_percent_max_w(
    dap_chain_net_id_t a_net_id);

#ifdef __cplusplus
}
#endif

