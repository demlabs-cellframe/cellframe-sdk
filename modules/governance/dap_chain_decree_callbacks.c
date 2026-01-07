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

#include "dap_chain_decree_callbacks.h"
#include <string.h>

// Global callbacks registry (initialized to all NULLs)
static dap_chain_decree_callbacks_t s_decree_callbacks = {0};

int dap_chain_decree_callbacks_register(const dap_chain_decree_callbacks_t *a_callbacks) {
    if (!a_callbacks)
        return -1;
    
    // Register each non-NULL callback
    if (a_callbacks->net_get_poa_keys)
        s_decree_callbacks.net_get_poa_keys = a_callbacks->net_get_poa_keys;
    
    if (a_callbacks->net_get_poa_keys_min_count)
        s_decree_callbacks.net_get_poa_keys_min_count = a_callbacks->net_get_poa_keys_min_count;
    
    if (a_callbacks->net_get_chains)
        s_decree_callbacks.net_get_chains = a_callbacks->net_get_chains;
    
    if (a_callbacks->net_get_ledger)
        s_decree_callbacks.net_get_ledger = a_callbacks->net_get_ledger;
    
    if (a_callbacks->net_get_fee_addr)
        s_decree_callbacks.net_get_fee_addr = a_callbacks->net_get_fee_addr;
    
    if (a_callbacks->net_get_name)
        s_decree_callbacks.net_get_name = a_callbacks->net_get_name;
    
    if (a_callbacks->stake_set_percent_max)
        s_decree_callbacks.stake_set_percent_max = a_callbacks->stake_set_percent_max;
    
    if (a_callbacks->stake_set_allowed_min_value)
        s_decree_callbacks.stake_set_allowed_min_value = a_callbacks->stake_set_allowed_min_value;
    
    if (a_callbacks->stake_get_total_keys)
        s_decree_callbacks.stake_get_total_keys = a_callbacks->stake_get_total_keys;
    
    if (a_callbacks->esbocs_set_signs_struct_check)
        s_decree_callbacks.esbocs_set_signs_struct_check = a_callbacks->esbocs_set_signs_struct_check;
    
    if (a_callbacks->esbocs_set_emergency_validator)
        s_decree_callbacks.esbocs_set_emergency_validator = a_callbacks->esbocs_set_emergency_validator;
    
    if (a_callbacks->esbocs_set_hardfork_prepare)
        s_decree_callbacks.esbocs_set_hardfork_prepare = a_callbacks->esbocs_set_hardfork_prepare;
    
    if (a_callbacks->esbocs_hardfork_engaged)
        s_decree_callbacks.esbocs_hardfork_engaged = a_callbacks->esbocs_hardfork_engaged;
    
    if (a_callbacks->esbocs_set_hardfork_complete)
        s_decree_callbacks.esbocs_set_hardfork_complete = a_callbacks->esbocs_set_hardfork_complete;
    
    if (a_callbacks->esbocs_set_empty_block_every_times)
        s_decree_callbacks.esbocs_set_empty_block_every_times = a_callbacks->esbocs_set_empty_block_every_times;
    
    if (a_callbacks->esbocs_get_min_validators_count)
        s_decree_callbacks.esbocs_get_min_validators_count = a_callbacks->esbocs_get_min_validators_count;
    
    return 0;
}

const dap_chain_decree_callbacks_t *dap_chain_decree_callbacks_get(void) {
    return &s_decree_callbacks;
}

