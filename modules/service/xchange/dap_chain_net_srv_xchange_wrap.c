/**
 * @file dap_chain_net_srv_xchange_wrap.c
 * @brief Wrapper functions for xchange service operations
 * 
 * This file implements wrapper functions for xchange operations that can be
 * mocked during unit testing using the DAP Mock Framework with --wrap linker flag.
 * 
 * Each wrapper function simply delegates to the real implementation,
 * but can be intercepted by mock wrappers during testing.
 * 
 * @author Cellframe Team
 * @copyright DeM Labs Inc. 2025
 * @license GPL-3.0
 */

#include "dap_chain_net_srv_xchange.h"
#include "dap_chain_net_srv_xchange_wrap.h"

/**
 * @brief Wrapper for getting order status
 * @param a_net Network pointer
 * @param a_order_tx_hash Order transaction hash
 * @return Order status
 */
dap_chain_net_srv_xchange_order_status_t dap_chain_net_srv_xchange_get_order_status_w(
    dap_chain_net_t *a_net, 
    dap_hash_fast_t a_order_tx_hash)
{
    return dap_chain_net_srv_xchange_get_order_status(a_net, a_order_tx_hash);
}

/**
 * @brief Wrapper for getting order completion rate
 * @param a_net Network pointer
 * @param a_order_tx_hash Order transaction hash
 * @return Completion rate percentage (0-100)
 */
uint64_t dap_chain_net_srv_xchange_get_order_completion_rate_w(
    dap_chain_net_t *a_net, 
    dap_hash_fast_t a_order_tx_hash)
{
    return dap_chain_net_srv_xchange_get_order_completion_rate(a_net, a_order_tx_hash);
}

/**
 * @brief Wrapper for getting xchange service fee
 * @param a_net_id Network ID
 * @param a_value Output: fee value
 * @param a_addr Output: fee address
 * @param a_type Output: fee type
 * @return true if fee is set, false otherwise
 */
bool dap_chain_net_srv_xchange_get_fee_w(
    dap_chain_net_id_t a_net_id, 
    uint256_t *a_value, 
    dap_chain_addr_t *a_addr, 
    uint16_t *a_type)
{
    return dap_chain_net_srv_xchange_get_fee(a_net_id, a_value, a_addr, a_type);
}

/**
 * @brief Wrapper for getting all xchange prices
 * @param a_net Network pointer
 * @return List of prices
 */
dap_list_t *dap_chain_net_srv_xchange_get_prices_w(dap_chain_net_t *a_net)
{
    return dap_chain_net_srv_xchange_get_prices(a_net);
}

/**
 * @brief Wrapper for getting xchange transactions
 * @param a_net Network pointer
 * @return List of transactions
 */
dap_list_t *dap_chain_net_srv_xchange_get_tx_xchange_w(dap_chain_net_t *a_net)
{
    return dap_chain_net_srv_xchange_get_tx_xchange(a_net);
}


