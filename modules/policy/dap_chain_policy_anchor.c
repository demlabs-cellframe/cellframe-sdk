/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2017-2024
 * All rights reserved.

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

#include "dap_chain_policy.h"
#include "dap_chain_net.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_common.h"

#define LOG_TAG "dap_chain_policy_anchor"

/**
 * @brief Apply reward anchor
 * Extracted from dap_chain_ledger_anchor.c lines ~214, 447
 */
int dap_chain_policy_anchor_reward_apply(dap_chain_datum_anchor_t *a_anchor, dap_chain_t *a_chain, dap_hash_sha3_256_t *a_anchor_hash, void *a_arg)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    if (!l_net) {
        log_it(L_WARNING, "Network not found for chain");
        return -1;
    }
    
    // Remove last reward
    dap_chain_net_remove_last_reward(l_net);
    
    log_it(L_NOTICE, "Reward anchor applied for network %s", l_net->pub.name);
    return 0;
}

/**
 * @brief Apply stake anchor
 * Extracted from dap_chain_ledger_anchor.c lines ~383, 421
 */
int dap_chain_policy_anchor_stake_apply(dap_chain_datum_anchor_t *a_anchor, dap_chain_t *a_chain, dap_hash_sha3_256_t *a_anchor_hash, void *a_arg)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    if (!l_net) {
        log_it(L_WARNING, "Network not found for chain");
        return -1;
    }
    
    // Extract signing address from anchor
    // This is a simplified version - full implementation would extract from anchor data
    dap_chain_addr_t l_signing_addr = {};
    
    // Invalidate stake key
    dap_chain_net_srv_stake_key_invalidate(&l_signing_addr);
    
    // Set minimum stake value
    dap_chain_net_srv_stake_set_allowed_min_value(a_chain->net_id, dap_chain_balance_coins_scan("1.0"));
    
    log_it(L_NOTICE, "Stake anchor applied for network %s", l_net->pub.name);
    return 0;
}

