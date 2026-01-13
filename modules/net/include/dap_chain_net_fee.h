/*
 * Network fee management API
 * Part of net core module (NO wallet dependency)
 */

#pragma once

#include "dap_chain_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get network fee
 * @param a_net_id Network ID  
 * @param a_value Output fee value
 * @param a_addr Output fee address
 * @return true if configured
 */
bool dap_chain_net_tx_get_fee(dap_chain_net_id_t a_net_id, uint256_t *a_value, dap_chain_addr_t *a_addr);

/**
 * @brief Set network fee
 * @param a_net_id Network ID
 * @param a_value Fee value
 * @param a_addr Fee address  
 * @return true on success
 */
bool dap_chain_net_tx_set_fee(dap_chain_net_id_t a_net_id, uint256_t a_value, dap_chain_addr_t a_addr);

#ifdef __cplusplus
}
#endif
