/*
 * Authors:
 * Daniil Frolov <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright (c) 2025, All rights reserved.
 *
 * This file is part of CellFrame SDK the open source project
 *
 *    CellFrame SDK is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    CellFrame SDK is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_decree_registry.h"
#include "dap_chain_net.h"
// REMOVED: #include "dap_chain_cs_esbocs.h" - TODO: resolve esbocs dependency
#include "dap_common.h"
#include "dap_hash.h"

#define LOG_TAG "stake_decree"

// Handler for STAKE_APPROVE decree
static int s_decree_stake_approve_handler(
    dap_chain_datum_decree_t *a_decree,
    dap_chain_net_t *a_net,
    bool a_apply,
    bool a_anchored)
{
    dap_hash_sha3_256_t l_hash = {};
    uint256_t l_value = {};
    dap_chain_addr_t l_addr = {};
    dap_chain_node_addr_t l_node_addr = {};
    
    if (dap_chain_datum_decree_get_hash(a_decree, &l_hash)){
        log_it(L_WARNING,"Can't get tx hash from decree.");
        return -105;
    }
    if (dap_chain_datum_decree_get_stake_value(a_decree, &l_value)){
        log_it(L_WARNING,"Can't get stake value from decree.");
        return -106;
    }
    if (dap_chain_datum_decree_get_stake_signing_addr(a_decree, &l_addr)){
        log_it(L_WARNING,"Can't get signing address from decree.");
        return -107;
    }
    if (dap_chain_datum_decree_get_node_addr(a_decree, &l_node_addr)){
        log_it(L_WARNING,"Can't get signer node address from decree.");
        return -108;
    }
    if (!a_anchored)
        return 0;
    if (dap_chain_net_srv_stake_verify_key_and_node(&l_addr, &l_node_addr)) {
        log_it(L_WARNING, "Key and node verification error");
        return -109;
    }
    if (!a_apply)
        return 0;
    dap_hash_sha3_256_t l_decree_hash = {};
    dap_hash_sha3_256(a_decree, dap_chain_datum_decree_get_size(a_decree), &l_decree_hash);
    dap_chain_net_srv_stake_key_delegate(a_net, &l_addr, &l_decree_hash, &l_hash, l_value, &l_node_addr, dap_chain_datum_decree_get_pkey(a_decree));
    if (!dap_chain_net_get_load_mode(a_net))
        dap_chain_net_srv_stake_add_approving_decree_info(a_decree, a_net);
    return 0;
}

// Handler for STAKE_PKEY_UPDATE decree
static int s_decree_stake_pkey_update_handler(
    dap_chain_datum_decree_t *a_decree,
    dap_chain_net_t *a_net,
    bool a_apply,
    bool a_anchored)
{
    if (!a_anchored)
        return 0;
    if (!a_apply)
        return 0;
    dap_pkey_t *l_pkey = NULL;
    if (! (l_pkey = dap_chain_datum_decree_get_pkey(a_decree)) ){
        log_it(L_WARNING,"Can't get pkey from decree.");
        return -105;
    }
    dap_chain_net_srv_stake_pkey_update(a_net, l_pkey);
    return 0;
}

// Handler for STAKE_INVALIDATE decree
static int s_decree_stake_invalidate_handler(
    dap_chain_datum_decree_t *a_decree,
    dap_chain_net_t *a_net,
    bool a_apply,
    bool a_anchored)
{
    dap_chain_addr_t l_addr = {};
    if (dap_chain_datum_decree_get_stake_signing_addr(a_decree, &l_addr)){
        log_it(L_WARNING,"Can't get signing address from decree.");
        return -105;
    }
    if (!a_anchored)
        return 0;
    
    // Minimum validators count should be checked by ESBOCS module decree handler
    // Stake module doesn't have direct dependency on ESBOCS (architectural layering)
    // If this check is needed, it should be done via decree validation chain where
    // ESBOCS handler validates consensus requirements before stake handler executes
    
    if (!a_apply)
        return 0;
    dap_chain_net_srv_stake_remove_approving_decree_info(a_net, &l_addr);
    dap_chain_net_srv_stake_key_invalidate(&l_addr);
    return 0;
}

// Handler for STAKE_MIN_VALUE decree
static int s_decree_stake_min_value_handler(
    dap_chain_datum_decree_t *a_decree,
    dap_chain_net_t *a_net,
    bool a_apply,
    bool a_anchored)
{
    UNUSED(a_anchored);
    uint256_t l_value = {};
    if (dap_chain_datum_decree_get_stake_min_value(a_decree, &l_value)){
        log_it(L_WARNING,"Can't get min stake value from decree.");
        return -105;
    }
    if (!a_apply)
        return 0;
    dap_chain_net_srv_stake_set_allowed_min_value(a_net->pub.id, l_value);
    return 0;
}

// Handler for STAKE_MIN_VALIDATORS_COUNT decree
static int s_decree_stake_min_validators_count_handler(
    dap_chain_datum_decree_t *a_decree,
    dap_chain_net_t *a_net,
    bool a_apply,
    bool a_anchored)
{
    uint256_t l_value = {};
    if (dap_chain_datum_decree_get_stake_min_signers_count(a_decree, &l_value)){
        log_it(L_WARNING,"Can't get min stake value from decree.");
        return -105;
    }
    dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
    if (!l_chain) {
        log_it(L_WARNING, "Specified chain not found");
        return -106;
    }
    if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
        log_it(L_WARNING, "Can't apply this decree to specified chain");
        return -115;
    }
    if (!a_anchored)
        return 0;
    uint16_t l_decree_count = (uint16_t)dap_chain_uint256_to(l_value);
    uint16_t l_current_count = dap_chain_net_srv_stake_get_total_keys(a_net->pub.id, NULL);
    if (l_decree_count > l_current_count) {
        log_it(L_WARNING, "Minimum validators count by decree %hu is greater than total validators count %hu in network %s",
                                                                    l_decree_count, l_current_count, a_net->pub.name);
        return -116;
    }
    if (!a_apply)
        return 0;
    
    // Setting min validators count should be done by ESBOCS module decree handler
    // This handler (s_decree_stake_min_validators_count_handler) should be moved to ESBOCS module
    // when ESBOCS is refactored. Stake module validates that we have enough validators,
    // but actual consensus parameter update is ESBOCS responsibility.
    log_it(L_WARNING, "ESBOCS min validators count update requires ESBOCS module (currently being refactored)");
    
    return 0;
}

// Handler for MAX_WEIGHT decree
static int s_decree_max_weight_handler(
    dap_chain_datum_decree_t *a_decree,
    dap_chain_net_t *a_net,
    bool a_apply,
    bool a_anchored)
{
    UNUSED(a_anchored);
    uint256_t l_value = {};
    if (dap_chain_datum_decree_get_value(a_decree, &l_value)) {
        log_it(L_WARNING,"Can't get value from decree.");
        return -105;
    }
    if ( compare256(l_value, GET_256_FROM_64(0)) <= 0 ||
         compare256(l_value, GET_256_FROM_64(100)) > 0 ) {
        log_it(L_WARNING,"Can't set max weight value. It must be > 0 and <= 100");
        return -106;
    }
    if (!a_apply)
        return 0;
    dap_chain_net_srv_stake_set_percent_max(a_net->pub.id, l_value);
    return 0;
}

// Registration function to be called from stake init
int dap_chain_net_srv_stake_decree_init(void)
{
    int l_ret = 0;
    
    // Register all stake-related decree handlers
    l_ret += dap_chain_decree_registry_register_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_APPROVE,
        s_decree_stake_approve_handler,
        "stake_approve"
    );
    
    l_ret += dap_chain_decree_registry_register_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_PKEY_UPDATE,
        s_decree_stake_pkey_update_handler,
        "stake_pkey_update"
    );
    
    l_ret += dap_chain_decree_registry_register_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_INVALIDATE,
        s_decree_stake_invalidate_handler,
        "stake_invalidate"
    );
    
    l_ret += dap_chain_decree_registry_register_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALUE,
        s_decree_stake_min_value_handler,
        "stake_min_value"
    );
    
    l_ret += dap_chain_decree_registry_register_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALIDATORS_COUNT,
        s_decree_stake_min_validators_count_handler,
        "stake_min_validators_count"
    );
    
    l_ret += dap_chain_decree_registry_register_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_MAX_WEIGHT,
        s_decree_max_weight_handler,
        "max_weight"
    );
    
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to register some stake decree handlers");
        return -1;
    }
    
    log_it(L_NOTICE, "Stake decree handlers registered successfully");
    return 0;
}

void dap_chain_net_srv_stake_decree_deinit(void)
{
    // Unregister all handlers
    dap_chain_decree_registry_unregister_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_APPROVE
    );
    dap_chain_decree_registry_unregister_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_PKEY_UPDATE
    );
    dap_chain_decree_registry_unregister_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_INVALIDATE
    );
    dap_chain_decree_registry_unregister_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALUE
    );
    dap_chain_decree_registry_unregister_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALIDATORS_COUNT
    );
    dap_chain_decree_registry_unregister_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_MAX_WEIGHT
    );
    
    log_it(L_NOTICE, "Stake decree handlers unregistered");
}
