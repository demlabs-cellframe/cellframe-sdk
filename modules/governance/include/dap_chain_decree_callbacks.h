/*
 * Authors:
 * Dmitriy Gerasimov <naeper@demlabs.net>
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 *
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

#pragma once

#include "dap_chain_common.h"
#include "dap_sign.h"
#include "dap_hash.h"

typedef struct dap_chain dap_chain_t;
typedef struct dap_chain_net dap_chain_net_t;

/**
 * @brief Decree callbacks API for breaking circular dependencies
 * @details Governance module doesn't depend directly on stake/esbocs/net modules.
 *          Instead, those modules register their callbacks when they initialize.
 */
typedef struct dap_chain_decree_callbacks {
    // Network configuration callbacks (to get PoA keys from net config)
    dap_list_t *(*net_get_poa_keys)(dap_chain_net_id_t a_net_id);  // Get list of PoA cert keys
    uint16_t (*net_get_poa_keys_min_count)(dap_chain_net_id_t a_net_id);  // Get minimum PoA signers count
    dap_chain_t *(*net_get_chains)(dap_chain_net_id_t a_net_id);  // Get chain list for network
    dap_ledger_t *(*net_get_ledger)(dap_chain_net_id_t a_net_id);  // Get ledger for network
    dap_chain_addr_t (*net_get_fee_addr)(dap_chain_net_id_t a_net_id);  // Get fee address for network
    const char *(*net_get_name)(dap_chain_net_id_t a_net_id);  // Get network name
    
    // Stake service callbacks
    void (*stake_set_percent_max)(dap_chain_net_id_t a_net_id, uint256_t a_value);
    void (*stake_set_allowed_min_value)(dap_chain_net_id_t a_net_id, uint256_t a_value);
    uint16_t (*stake_get_total_keys)(dap_chain_net_id_t a_net_id, uint256_t *a_total_weight);
    
    // ESBOCS consensus callbacks  
    int (*esbocs_set_signs_struct_check)(dap_chain_t *a_chain, bool a_enabled);
    int (*esbocs_set_emergency_validator)(dap_chain_t *a_chain, bool a_action, dap_sign_type_t a_sign_type, dap_hash_fast_t *a_hash);
    int (*esbocs_set_hardfork_prepare)(dap_chain_t *a_chain, uint64_t a_hardfork_gen, uint64_t a_block_num, void *a_addrs, void *a_changed_addrs_json);
    bool (*esbocs_hardfork_engaged)(dap_chain_t *a_chain);
    int (*esbocs_set_hardfork_complete)(dap_chain_t *a_chain);
    int (*esbocs_set_empty_block_every_times)(dap_chain_t *a_chain, uint256_t a_blockgen_period);
    uint16_t (*esbocs_get_min_validators_count)(dap_chain_net_id_t a_net_id);
} dap_chain_decree_callbacks_t;

/**
 * @brief Register decree callbacks from stake/esbocs modules
 * @param a_callbacks Pointer to callbacks structure (may contain NULL for unavailable callbacks)
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_decree_callbacks_register(const dap_chain_decree_callbacks_t *a_callbacks);

/**
 * @brief Get current registered callbacks
 * @return Pointer to callbacks structure (never NULL, but callbacks inside may be NULL)
 */
const dap_chain_decree_callbacks_t *dap_chain_decree_callbacks_get(void);

