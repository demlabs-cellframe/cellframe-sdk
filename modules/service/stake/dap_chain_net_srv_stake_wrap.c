/**
 * @file dap_chain_net_srv_stake_wrap.c
 * @brief Wrapper functions for stake service operations
 * 
 * This file implements wrapper functions for stake operations that can be
 * mocked during unit testing using the DAP Mock Framework with --wrap linker flag.
 * 
 * Each wrapper function simply delegates to the real implementation,
 * but can be intercepted by mock wrappers during testing.
 * 
 * @author Cellframe Team
 * @copyright DeM Labs Inc. 2025
 * @license GPL-3.0
 */

#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_net_srv_stake_wrap.h"

/**
 * @brief Wrapper for getting validators list
 */
dap_list_t *dap_chain_net_srv_stake_get_validators_w(
    dap_chain_net_id_t a_net_id, 
    bool a_only_active, 
    uint16_t **a_excluded_list)
{
    return dap_chain_net_srv_stake_get_validators(a_net_id, a_only_active, a_excluded_list);
}

/**
 * @brief Wrapper for getting total stake weight
 */
uint256_t dap_chain_net_srv_stake_get_total_weight_w(
    dap_chain_net_id_t a_net_id, 
    uint256_t *a_locked_weight)
{
    return dap_chain_net_srv_stake_get_total_weight(a_net_id, a_locked_weight);
}

/**
 * @brief Wrapper for getting total number of delegated keys
 */
size_t dap_chain_net_srv_stake_get_total_keys_w(
    dap_chain_net_id_t a_net_id, 
    size_t *a_in_active_count)
{
    return dap_chain_net_srv_stake_get_total_keys(a_net_id, a_in_active_count);
}

/**
 * @brief Wrapper for getting minimum allowed stake value
 */
uint256_t dap_chain_net_srv_stake_get_allowed_min_value_w(
    dap_chain_net_id_t a_net_id)
{
    return dap_chain_net_srv_stake_get_allowed_min_value(a_net_id);
}

/**
 * @brief Wrapper for checking validator
 */
int dap_chain_net_srv_stake_check_validator_w(
    dap_chain_net_t *a_net, 
    dap_hash_fast_t *a_tx_hash, 
    dap_chain_ch_validator_test_t *out_data,
    int a_time_connect, 
    int a_time_response)
{
    return dap_chain_net_srv_stake_check_validator(a_net, a_tx_hash, out_data, a_time_connect, a_time_response);
}

/**
 * @brief Wrapper for getting maximum stake percentage
 */
uint256_t dap_chain_net_srv_stake_get_percent_max_w(
    dap_chain_net_id_t a_net_id)
{
    return dap_chain_net_srv_stake_get_percent_max(a_net_id);
}


