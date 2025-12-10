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
#include "dap_chain_cs_esbocs.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_common.h"
#include "dap_common.h"
#include "dap_math_ops.h"
#include "dap_strfuncs.h"
#include "dap_json.h"
#include "dap_tsd.h"

#define LOG_TAG "dap_chain_policy_decree"

/**
 * @brief Apply fee decree
 * Extracted from dap_chain_ledger_decree.c lines ~380-392
 */
int dap_chain_policy_decree_fee_apply(dap_chain_datum_decree_t *a_decree, dap_chain_t *a_chain, bool a_apply, void *a_arg)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    if (!l_net) {
        log_it(L_WARNING, "Network not found for chain");
        return -1;
    }
    
    uint256_t l_value = uint256_0;
    dap_chain_addr_t l_addr = {};
    
    if (dap_chain_datum_decree_get_fee(a_decree, &l_value)) {
        log_it(L_WARNING, "Can't get fee value from decree");
        return -103;
    }
    
    if (dap_chain_datum_decree_get_fee_addr(a_decree, &l_addr)) {
        if (dap_chain_addr_is_blank(&l_net->pub.fee_addr)) {
            log_it(L_WARNING, "Fee wallet address not set");
            return -111;
        } else {
            l_addr = l_net->pub.fee_addr;
        }
    }
    
    if (!a_apply)
        return 0;
    
    if (!dap_chain_net_tx_set_fee(l_net->pub.id, l_value, l_addr)) {
        log_it(L_ERROR, "Can't set fee value for network %s", l_net->pub.name);
        return -1;
    }
    
    log_it(L_NOTICE, "Fee decree applied for network %s", l_net->pub.name);
    return 0;
}

/**
 * @brief Apply validators decree
 */
int dap_chain_policy_decree_validators_apply(dap_chain_datum_decree_t *a_decree, dap_chain_t *a_chain, bool a_apply, void *a_arg)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    if (!l_net) {
        log_it(L_WARNING, "Network not found for chain");
        return -1;
    }
    
    if (dap_strcmp(dap_chain_get_cs_type(a_chain), "esbocs")) {
        log_it(L_WARNING, "Can't apply validators decree to non-esbocs chain");
        return -115;
    }
    
    if (!a_apply)
        return 0;
    
    // Call esbocs function to set validators
    if (dap_chain_esbocs_set_min_validators_count(a_chain, 0) != 0) {
        log_it(L_ERROR, "Failed to set validators count");
        return -1;
    }
    
    log_it(L_NOTICE, "Validators decree applied for chain %s", a_chain->name);
    return 0;
}

/**
 * @brief Apply hardfork decree
 * Extracted from dap_chain_ledger_decree.c lines ~419-467
 */
int dap_chain_policy_decree_hardfork_apply(dap_chain_datum_decree_t *a_decree, dap_chain_t *a_chain, bool a_apply, void *a_arg)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    if (!l_net) {
        log_it(L_WARNING, "Network not found for chain");
        return -1;
    }
    
    uint64_t l_block_num = 0;
    if (dap_chain_datum_decree_get_atom_num(a_decree, &l_block_num)) {
        log_it(L_WARNING, "Can't get atom number from hardfork prepare decree");
        return -103;
    }
    
    if (dap_strcmp(dap_chain_get_cs_type(a_chain), "esbocs")) {
        log_it(L_WARNING, "Can't apply this decree to non-esbocs chain");
        return -115;
    }
    
    dap_tsd_t *l_generation = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, 
                                           DAP_CHAIN_DATUM_DECREE_TSD_TYPE_GENERATION);
    if (!l_generation || l_generation->size != sizeof(uint16_t)) {
        log_it(L_WARNING, "Can't apply this decree, it has no chain generation set");
        return -116;
    }
    
    uint16_t l_hardfork_generation = *(uint16_t *)l_generation->data;
    if (l_hardfork_generation <= a_chain->generation) {
        log_it(L_WARNING, "Invalid hardfork generation %hu, current generation is %hu", 
               l_hardfork_generation, a_chain->generation);
        return -117;
    }
    
    if (!a_apply)
        return 0;
    
    // Collect node addresses
    dap_list_t *l_addrs = NULL;
    dap_list_t *l_addrs_tsd = dap_tsd_find_all(a_decree->data_n_signs, a_decree->header.data_size,
                                                DAP_CHAIN_DATUM_DECREE_TSD_TYPE_NODE_ADDR, 
                                                sizeof(dap_stream_node_addr_t));
    for (dap_list_t *it = l_addrs_tsd; it; it = it->next) {
        dap_tsd_t *l_tsd = (dap_tsd_t *)it->data;
        if (l_tsd->size != sizeof(dap_stream_node_addr_t)) {
            log_it(L_WARNING, "Invalid size of node addr tsd");
            continue;
        }
        dap_stream_node_addr_t *l_addr = (dap_stream_node_addr_t *)l_tsd->data;
        l_addrs = dap_list_append(l_addrs, DAP_DUP(l_addr));
    }
    dap_list_free_full(l_addrs_tsd, NULL);
    
    dap_tsd_t *l_changed_addrs = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, 
                                              DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HARDFORK_CHANGED_ADDRS);
    dap_json_tokener_error_t l_error;
    dap_json_t *l_changed_addrs_json = l_changed_addrs ? 
        dap_json_tokener_parse_verbose((char *)l_changed_addrs->data, &l_error) : NULL;
    
    int l_ret = dap_chain_esbocs_set_hardfork_prepare(a_chain, l_hardfork_generation, 
                                                       l_block_num, l_addrs, l_changed_addrs_json);
    
    log_it(L_NOTICE, "Hardfork decree applied for chain %s", a_chain->name);
    return l_ret;
}

/**
 * @brief Apply stake minimum decree
 */
int dap_chain_policy_decree_stake_min_apply(dap_chain_datum_decree_t *a_decree, dap_chain_t *a_chain, bool a_apply, void *a_arg)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    if (!l_net) {
        log_it(L_WARNING, "Network not found for chain");
        return -1;
    }
    
    if (!a_apply)
        return 0;
    
    // Set minimum stake value
    dap_chain_net_srv_stake_set_allowed_min_value(a_chain->net_id, dap_chain_balance_coins_scan("1.0"));
    
    log_it(L_NOTICE, "Stake minimum decree applied for network");
    return 0;
}

