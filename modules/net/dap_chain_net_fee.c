/*
 * Authors:
 * Cellframe Development Team  
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 *
 * Network fee management functions
 * Moved to net/core to break mempool ↔ net-tx cycle
 */

#include "dap_chain_net_core.h"  // For dap_chain_net_by_id
#include "dap_chain_net_fee.h"
#include "dap_common.h"

#define LOG_TAG "dap_chain_net_fee"

/**
 * @brief Get network fee value and address
 * @param a_net_id Network ID
 * @param a_value Output fee value
 * @param a_addr Output fee address
 * @return true if fee is configured, false otherwise
 */
bool dap_chain_net_tx_get_fee(dap_chain_net_id_t a_net_id, uint256_t *a_value, dap_chain_addr_t *a_addr)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_net_id);
    if (!l_net){
        log_it(L_WARNING, "Can't find net with id 0x%016"DAP_UINT64_FORMAT_x"", a_net_id.uint64);
        return false;
    }
    if (IS_ZERO_256(l_net->pub.fee_value))
        return false;
    if (a_value)
        *a_value = l_net->pub.fee_value;
    if (a_addr)
        *a_addr = l_net->pub.fee_addr;
    return true;
}

/**
 * @brief Set network fee value and address
 * @param a_net_id Network ID
 * @param a_value Fee value
 * @param a_addr Fee address
 * @return true on success
 */
bool dap_chain_net_tx_set_fee(dap_chain_net_id_t a_net_id, uint256_t a_value, dap_chain_addr_t a_addr)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_net_id);
    if (!l_net){
        log_it(L_WARNING, "Can't find net with id 0x%016"DAP_UINT64_FORMAT_x"", a_net_id.uint64);
        return false;
    }
    l_net->pub.fee_value = a_value;
    l_net->pub.fee_addr = a_addr;
    return true;
}
